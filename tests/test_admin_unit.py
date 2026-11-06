import ast
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch
from datetime import datetime, timezone
from xml.etree import ElementTree as ET
import zipfile
from guard_admin import Sessions, ADMIN_FIELDS, event_rows, merge_settings, xlsx_bytes

class AdminUnitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/'test.db'
        c=self.connect()
        c.execute("""CREATE TABLE events(id INTEGER PRIMARY KEY,ts REAL,request_id TEXT,
                  origin TEXT,decision TEXT,code TEXT,ms INTEGER,query_text TEXT,
                  event_type TEXT NOT NULL DEFAULT 'SEARCH',username TEXT)""")
        c.commit();c.close()
        self.sessions=Sessions(self.connect,'admin','a'*32,json.dumps({'officer1':'b'*32}))
    def tearDown(self):
        self.tmp.cleanup()
    def connect(self):
        c=sqlite3.connect(self.path);c.row_factory=sqlite3.Row;return c
    def insert(self,decision='ALLOW',username=None,ts=None,text='synthetic'):
        c=self.connect()
        with c:
            c.execute('INSERT INTO events(ts,decision,username,event_type,query_text) VALUES(?,?,?,?,?)',
                      (time.time() if ts is None else ts,decision,username,'SEARCH',text))
        c.close()
    def test_admin_login_and_auth_event(self):
        token,user=self.sessions.login('admin','a'*32)
        self.assertTrue(user.is_admin)
        self.assertEqual(self.sessions.current(token),user)
        rows=event_rows(self.connect,'AUTH')
        self.assertEqual(len(rows),1)
        self.assertEqual((rows[0]['username'],rows[0]['code']),('admin','LOGIN_SUCCESS'))
        self.assertIsNone(rows[0]['query_text'])
    def test_operator_login(self):
        token,user=self.sessions.login('officer1','b'*32)
        self.assertFalse(user.is_admin)
        self.assertEqual(self.sessions.current(token).username,'officer1')
    def test_wrong_credentials_create_no_session(self):
        for name,password in [('admin','wrong'),('unknown','b'*32)]:
            with self.assertRaises(PermissionError):self.sessions.login(name,password)
        self.assertEqual(event_rows(self.connect),[])
    def test_token_not_stored_plaintext(self):
        token,_=self.sessions.login('admin','a'*32)
        c=self.connect();row=c.execute('SELECT * FROM ui_sessions').fetchone();c.close()
        self.assertNotEqual(row['token_hash'],token)
        self.assertNotIn(token,tuple(row))
    def test_logout_revokes(self):
        token,_=self.sessions.login('admin','a'*32)
        self.sessions.logout(token)
        self.assertIsNone(self.sessions.current(token))
    def test_expiration(self):
        token,_=self.sessions.login('admin','a'*32)
        c=self.connect()
        with c:c.execute('UPDATE ui_sessions SET expires=?',(time.time()-1,))
        c.close();self.assertIsNone(self.sessions.current(token))
    def test_password_change_revokes_existing_session(self):
        token,_=self.sessions.login('officer1','b'*32)
        updated=Sessions(self.connect,'admin','a'*32,json.dumps({'officer1':'c'*32}))
        self.assertIsNone(updated.current(token))
    def test_account_removal_revokes(self):
        token,_=self.sessions.login('officer1','b'*32)
        updated=Sessions(self.connect,'admin','a'*32,'{}')
        self.assertIsNone(updated.current(token))
    def test_invalid_account_config(self):
        invalid=['[]','{"admin":"'+('b'*32)+'"}', '{"x":"short"}',
                 '{"x":"'+('b'*32)+'","x":"'+('c'*32)+'"}']
        for payload in invalid:
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):Sessions(self.connect,'admin','a'*32,payload)
    def test_all_nine_admin_fields_protected(self):
        self.assertEqual(len(ADMIN_FIELDS),9)
        old={k:'old' for k in ADMIN_FIELDS};old['policy']='old policy'
        for key in ADMIN_FIELDS:
            with self.assertRaises(PermissionError):merge_settings(old,{key:'new'},False)
        self.assertEqual(merge_settings(old,{'policy':'new'},False)['policy'],'new')
        self.assertEqual(merge_settings(old,{'region':'225'},True)['region'],'225')
    def test_unknown_setting_and_blank_key(self):
        with self.assertRaises(ValueError):merge_settings({'policy':'x'},{'unknown':'x'},True)
        merged=merge_settings({'llm_key':'old','yandex_key':'old'},{'llm_key':'','yandex_key':''},True)
        self.assertEqual(merged,{'llm_key':'old','yandex_key':'old'})
    def test_filter_excludes_auth_from_search_allow(self):
        self.sessions.login('officer1','b'*32)
        self.insert('ALLOW','officer1');self.insert('BLOCK','admin')
        self.assertEqual(len(event_rows(self.connect,'ALL')),3)
        self.assertEqual(len(event_rows(self.connect,'ALLOW')),1)
        self.assertEqual(len(event_rows(self.connect,'AUTH')),1)
        self.assertEqual(len(event_rows(self.connect,'ALL','officer1')),2)
        self.assertEqual(event_rows(self.connect,'ALL',"' OR 1=1 --"),[])
    def test_utc_date_filters(self):
        stamp=datetime(2026,11,6,12,tzinfo=timezone.utc).timestamp()
        self.insert(ts=stamp);self.insert(ts=stamp-86400)
        self.assertEqual(len(event_rows(self.connect,date_from='2026-11-06',date_to='2026-11-06')),1)
        for filters in [{'decision':'INVALID'},{'date_from':'2026-02-30'},
                        {'date_from':'2026-11-07','date_to':'2026-11-06'}]:
            with self.assertRaises(ValueError):event_rows(self.connect,**filters)
    def test_export_selects_more_than_200(self):
        for _ in range(205):self.insert()
        self.assertEqual(len(event_rows(self.connect,limit=200)),200)
        self.assertEqual(len(event_rows(self.connect)),205)
        workbook=xlsx_bytes(event_rows(self.connect))
        with zipfile.ZipFile(io.BytesIO(workbook)) as z:
            root=ET.fromstring(z.read('xl/worksheets/sheet1.xml'))
            self.assertEqual(len(root.findall('.//{*}row')),206)
    def test_xlsx_text_not_formula_and_xml_controls(self):
        self.insert(text='=HYPERLINK("https://example.invalid","test")\x00<&')
        self.sessions.login('admin','a'*32)
        workbook=xlsx_bytes(event_rows(self.connect))
        with zipfile.ZipFile(io.BytesIO(workbook)) as z:
            root=ET.fromstring(z.read('xl/worksheets/sheet1.xml'))
            self.assertEqual(root.findall('.//{*}f'),[])
            cells=root.findall('.//{*}c')
            self.assertTrue(all(c.attrib['t']=='inlineStr' for c in cells))
            self.assertIn('=HYPERLINK',z.read('xl/worksheets/sheet1.xml').decode())
    def test_empty_xlsx_is_valid(self):
        with zipfile.ZipFile(io.BytesIO(xlsx_bytes([]))) as z:
            self.assertEqual(z.testzip(),None)
            root=ET.fromstring(z.read('xl/worksheets/sheet1.xml'))
            self.assertEqual(len(root.findall('.//{*}row')),1)
    def test_additive_migration_keeps_previous_records(self):
        path=Path(self.tmp.name)/'legacy.db'
        def connect():
            c=sqlite3.connect(path);c.row_factory=sqlite3.Row;return c
        c=connect()
        c.executescript("CREATE TABLE events(id INTEGER PRIMARY KEY,ts REAL,request_id TEXT,origin TEXT,decision TEXT,code TEXT,ms INTEGER,rejected_query TEXT);")
        c.execute('INSERT INTO events(ts,decision,rejected_query) VALUES(?,?,?)',(time.time(),'BLOCK','old synthetic text'))
        c.commit();c.close()
        source=Path(__file__).resolve().parents[1]/'app.py'
        tree=ast.parse(source.read_text())
        nodes=[];inside=False
        for n in tree.body:
            if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='conn' for t in n.targets):inside=True
            if inside:nodes.append(n)
            if inside and isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute) and isinstance(n.value.func.value,ast.Name) and n.value.func.value.id=='conn' and n.value.func.attr=='close':break
        compiled=compile(ast.Module(body=nodes,type_ignores=[]),'migration','exec')
        for _ in range(2):exec(compiled,{'connect':connect,'time':time})
        c=connect();row=c.execute('SELECT * FROM events').fetchone();c.close()
        self.assertEqual(row['query_text'],'old synthetic text')
        self.assertEqual(row['event_type'],'SEARCH')
        self.assertIsNone(row['username'])

if __name__=='__main__':unittest.main(verbosity=2)
