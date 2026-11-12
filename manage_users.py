"""Explicit offline legacy-account import; no passwords in CLI arguments."""
import argparse
import os
from pathlib import Path
import sqlite3
from guard_accounts import AccountStore, AccountError

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--import-legacy-users',action='store_true',required=True)
    parser.parse_args()
    raw=os.environ.get('GUARD_USERS_JSON','')
    if not raw or len(raw)>65536:parser.error('Set GUARD_USERS_JSON for this explicit import')
    db=Path(os.environ.get('DATA_DIR','/data'))/'guard.db'
    if not db.is_file():parser.error('Existing guard.db required; start application first')
    def connect():
        c=sqlite3.connect(db,timeout=5);c.row_factory=sqlite3.Row;return c
    admin=os.environ.get('ADMIN_USER','admin')
    try:
        count=AccountStore(connect,admin).import_legacy(admin,raw)
    except (ValueError,PermissionError):
        parser.error('Import rejected; check names, password lengths, collisions and previous import; no values printed')
    print(f'Imported {count} operator accounts. Remove GUARD_USERS_JSON from env and recreate the service.')

if __name__=='__main__':main()
