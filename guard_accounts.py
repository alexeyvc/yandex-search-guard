"""SQLite operator accounts and revocable, database-backed UI sessions."""
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import uuid
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from guard_admin import User

class AccountError(ValueError):
    pass

class LoginBusy(Exception):
    pass

class AccountStore:
    def __init__(self, connect, admin_user):
        self.connect, self.admin_user = connect, admin_user
        self.hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
        self.dummy = self.hasher.hash(secrets.token_urlsafe(32))
        c = connect()
        try:
            with c:
                c.execute('CREATE TABLE IF NOT EXISTS operator_accounts(username TEXT PRIMARY KEY,password_hash TEXT NOT NULL,enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),revision TEXT NOT NULL,created_at REAL NOT NULL,updated_at REAL NOT NULL)')
                c.execute('CREATE TABLE IF NOT EXISTS account_audit(id INTEGER PRIMARY KEY,ts REAL NOT NULL,actor TEXT NOT NULL,target TEXT NOT NULL,action TEXT NOT NULL)')
                c.execute('CREATE TABLE IF NOT EXISTS account_migrations(name TEXT PRIMARY KEY,ts REAL NOT NULL)')
                if c.execute('SELECT 1 FROM operator_accounts WHERE username=?',(admin_user,)).fetchone():
                    raise AccountError('ADMIN_USER conflicts with a database operator')
        finally:
            c.close()

    @staticmethod
    def validate(username, password=None):
        if not isinstance(username,str) or not re.fullmatch(r'[A-Za-z0-9_.@-]{1,64}',username):
            raise AccountError('Invalid username')
        if password is not None and (not isinstance(password,str) or not 24 <= len(password) <= 512):
            raise AccountError('Password must have 24..512 characters')

    def _check(self, actor, username=None):
        if actor != self.admin_user:
            raise PermissionError('Administrator required')
        if username is not None:
            self.validate(username)
            if username == self.admin_user:
                raise AccountError('Administrator credentials are configured in env')

    @staticmethod
    def revoke(c, username):
        if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ui_sessions'").fetchone():
            c.execute('DELETE FROM ui_sessions WHERE username=?',(username,))

    @staticmethod
    def audit(c, actor, target, action):
        now=time.time()
        c.execute('INSERT INTO account_audit(ts,actor,target,action) VALUES(?,?,?,?)',(now,actor,target,action))
        c.execute('DELETE FROM account_audit WHERE ts<?',(now-30*86400,))
        c.execute('DELETE FROM account_audit WHERE id<=COALESCE((SELECT MAX(id)-10000 FROM account_audit),0)')

    def list_accounts(self, actor):
        self._check(actor)
        c=self.connect()
        try:
            return [dict(r) for r in c.execute('SELECT username,enabled,created_at,updated_at FROM operator_accounts ORDER BY username')]
        finally:c.close()

    def audit_rows(self, actor):
        self._check(actor);c=self.connect()
        try:
            with c:c.execute('DELETE FROM account_audit WHERE ts<?',(time.time()-30*86400,))
            return [dict(r) for r in c.execute('SELECT ts,actor,target,action FROM account_audit ORDER BY id DESC LIMIT 200')]
        finally:c.close()

    def create(self, actor, username, password):
        self._check(actor,username);self.validate(username,password)
        hashed=self.hasher.hash(password);now=time.time();c=self.connect()
        try:
            with c:
                c.execute('BEGIN IMMEDIATE')
                if c.execute('SELECT COUNT(*) FROM operator_accounts').fetchone()[0]>=99:
                    raise AccountError('At most 99 operators')
                if c.execute('SELECT 1 FROM operator_accounts WHERE username=?',(username,)).fetchone():
                    raise AccountError('Account already exists')
                c.execute('INSERT INTO operator_accounts VALUES(?,?,1,?,?,?)',(username,hashed,uuid.uuid4().hex,now,now))
                self.revoke(c,username);self.audit(c,actor,username,'USER_CREATED')
        finally:c.close()

    def change(self, actor, username, *, password=None, enabled=None, delete=False):
        self._check(actor,username)
        if sum((password is not None, enabled is not None, delete))!=1:
            raise AccountError('Exactly one account change required')
        hashed=None
        if password is not None:
            self.validate(username,password);hashed=self.hasher.hash(password)
        if enabled is not None and type(enabled) is not bool:
            raise AccountError('enabled must be boolean')
        c=self.connect()
        try:
            with c:
                c.execute('BEGIN IMMEDIATE')
                if not c.execute('SELECT 1 FROM operator_accounts WHERE username=?',(username,)).fetchone():
                    raise AccountError('Account not found')
                if delete:
                    c.execute('DELETE FROM operator_accounts WHERE username=?',(username,));action='USER_DELETED'
                elif hashed:
                    c.execute('UPDATE operator_accounts SET password_hash=?,revision=?,updated_at=? WHERE username=?',(hashed,uuid.uuid4().hex,time.time(),username));action='USER_PASSWORD_RESET'
                else:
                    c.execute('UPDATE operator_accounts SET enabled=?,revision=?,updated_at=? WHERE username=?',(int(enabled),uuid.uuid4().hex,time.time(),username));action='USER_ENABLED' if enabled else 'USER_DISABLED'
                self.revoke(c,username);self.audit(c,actor,username,action)
        finally:c.close()

    def import_legacy(self, actor, raw):
        self._check(actor)
        def unique(items):
            d={}
            for k,v in items:
                if k in d:raise AccountError('Duplicate account')
                d[k]=v
            return d
        data=json.loads(raw,object_pairs_hook=unique)
        if not isinstance(data,dict) or len(data)>99:raise AccountError('Invalid import')
        for name,password in data.items():
            self._check(actor,name)
            if not isinstance(password,str):raise AccountError('Invalid password')
            self.validate(name,password)
        rows=[(n,self.hasher.hash(p)) for n,p in data.items()]
        c=self.connect()
        try:
            with c:
                c.execute('BEGIN IMMEDIATE')
                if c.execute("SELECT 1 FROM account_migrations WHERE name='legacy-users'").fetchone():
                    raise AccountError('Import already completed')
                if c.execute('SELECT COUNT(*) FROM operator_accounts').fetchone()[0]+len(rows)>99:
                    raise AccountError('At most 99 operators')
                for name,hashed in rows:
                    if c.execute('SELECT 1 FROM operator_accounts WHERE username=?',(name,)).fetchone():
                        raise AccountError('Import would overwrite an account')
                    now=time.time()
                    c.execute('INSERT INTO operator_accounts VALUES(?,?,1,?,?,?)',(name,hashed,uuid.uuid4().hex,now,now))
                    self.revoke(c,name);self.audit(c,actor,name,'USER_IMPORTED')
                c.execute("INSERT INTO account_migrations VALUES('legacy-users',?)",(time.time(),))
        finally:c.close()
        return len(rows)

class DatabaseSessions:
    def __init__(self, connect, admin_user, admin_password, store=None, hours=8):
        AccountStore.validate(admin_user,admin_password)
        if not 1<=int(hours)<=168:raise ValueError('SESSION_HOURS must be 1..168')
        self.connect,self.admin_user,self.admin_password=connect,admin_user,admin_password
        self.store=store or AccountStore(connect,admin_user)
        self.ttl=int(hours)*3600
        self._login_slots=threading.BoundedSemaphore(2)
        self._attempt_lock=threading.Lock();self._attempts=[]
        c=connect()
        try:
            with c:
                c.execute('CREATE TABLE IF NOT EXISTS ui_sessions(token_hash TEXT PRIMARY KEY,username TEXT NOT NULL,expires REAL NOT NULL,csrf_token TEXT NOT NULL,credential_tag TEXT NOT NULL)')
                c.execute('DELETE FROM ui_sessions WHERE expires<=?',(time.time(),))
        finally:c.close()

    @staticmethod
    def token_hash(token):return hashlib.sha256(token.encode()).hexdigest()

    def _tag(self, username, digest, revision=None):
        if username==self.admin_user:
            return 'admin-v4:'+hmac.new(self.admin_password.encode(),digest.encode(),hashlib.sha256).hexdigest()
        return 'operator-v4:'+revision

    def _admit(self):
        now=time.monotonic()
        with self._attempt_lock:
            self._attempts=[t for t in self._attempts if t>now-60]
            if len(self._attempts)>=60:raise LoginBusy('Login rate exceeded')
            self._attempts.append(now)
        if not self._login_slots.acquire(blocking=False):raise LoginBusy('Login workers busy')

    def login(self, username, password):
        if not isinstance(username,str) or not isinstance(password,str) or len(username)>64 or not 1<=len(password)<=512:
            raise PermissionError('Invalid credentials')
        self._admit()
        try:
            revision=None
            if username==self.admin_user:
                valid=secrets.compare_digest(hashlib.sha256(password.encode()).digest(),hashlib.sha256(self.admin_password.encode()).digest())
            else:
                c=self.connect()
                try:row=c.execute('SELECT * FROM operator_accounts WHERE username=?',(username,)).fetchone()
                finally:c.close()
                try:valid=self.store.hasher.verify(row['password_hash'] if row else self.store.dummy,password)
                except (VerificationError,InvalidHashError):valid=False
                valid=bool(valid and row and row['enabled'])
                if valid:revision=row['revision']
            if not valid:raise PermissionError('Invalid credentials')
            token,csrf=secrets.token_urlsafe(32),secrets.token_urlsafe(32)
            digest,now=self.token_hash(token),time.time();c=self.connect()
            try:
                with c:
                    c.execute('BEGIN IMMEDIATE')
                    if username!=self.admin_user:
                        current=c.execute('SELECT enabled,revision FROM operator_accounts WHERE username=?',(username,)).fetchone()
                        if not current or not current['enabled'] or current['revision']!=revision:
                            raise PermissionError('Credentials changed during login')
                    c.execute('DELETE FROM ui_sessions WHERE expires<=?',(now,))
                    c.execute('INSERT INTO ui_sessions VALUES(?,?,?,?,?)',(digest,username,now+self.ttl,csrf,self._tag(username,digest,revision)))
                    c.execute('INSERT INTO events(ts,request_id,origin,decision,code,ms,query_text,event_type,username) VALUES(?,?,?,?,?,?,?,?,?)',(now,uuid.uuid4().hex,'auth','ALLOW','LOGIN_SUCCESS',0,None,'AUTH',username))
                    c.execute('DELETE FROM events WHERE ts<?',(now-30*86400,))
                    c.execute('DELETE FROM events WHERE id<=COALESCE((SELECT MAX(id)-10000 FROM events),0)')
            finally:c.close()
            return token,User(username,username==self.admin_user,csrf)
        finally:self._login_slots.release()

    def current(self, token):
        if not isinstance(token,str) or not 20<=len(token)<=256:return None
        digest=self.token_hash(token);c=self.connect()
        try:
            row=c.execute('SELECT s.*,a.enabled AS account_enabled,a.revision AS account_revision FROM ui_sessions s LEFT JOIN operator_accounts a ON a.username=s.username WHERE token_hash=?',(digest,)).fetchone()
            if not row:return None
            valid=row['expires']>time.time()
            if row['username']==self.admin_user:
                expected=self._tag(self.admin_user,digest)
            elif row['account_enabled'] and row['account_revision']:
                expected=self._tag(row['username'],digest,row['account_revision'])
            else:valid=False;expected=''
            valid=valid and secrets.compare_digest(row['credential_tag'],expected)
            if not valid:
                with c:c.execute('DELETE FROM ui_sessions WHERE token_hash=?',(digest,))
                return None
            return User(row['username'],row['username']==self.admin_user,row['csrf_token'])
        finally:c.close()

    def logout(self, token):
        if not token:return
        c=self.connect()
        try:
            with c:c.execute('DELETE FROM ui_sessions WHERE token_hash=?',(self.token_hash(token),))
        finally:c.close()
