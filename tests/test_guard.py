import json
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

_tmp=tempfile.TemporaryDirectory()
os.environ.update(DATA_DIR=_tmp.name,ADMIN_USER='admin',ADMIN_PASSWORD='a'*32,
                  SEARCH_TOKEN='b'*32,GUARD_USERS_JSON=json.dumps({'officer1':'c'*32}),
                  SESSION_COOKIE_SECURE='true')
import app as guard
from fastapi.testclient import TestClient

class GuardTests(unittest.TestCase):
    def setUp(self):
        c=guard.connect()
        with c:
            for table in ('events','config','ui_sessions'):c.execute('DELETE FROM '+table)
        c.close()
        self.client=TestClient(guard.app,base_url='https://testserver',raise_server_exceptions=False)
        self.client.__enter__()
        self.ui={}
        self.login('admin','a'*32)
        self.headers={'Authorization':'Api-Key '+'b'*32}
        self.s=guard.Settings(llm_model='local-classifier',yandex_key='TEST_ONLY_KEY',folder_id='server-folder')
        self.body={'query':{'queryText':'PostgreSQL replication','searchType':'SEARCH_TYPE_RU'},'responseFormat':'FORMAT_XML'}
    def tearDown(self):self.client.__exit__(None,None,None)
    def login(self,username,password):
        r=self.client.post('/api/login',json={'username':username,'password':password},headers={'X-Guard-UI':'1'})
        self.assertEqual(r.status_code,200,r.text)
        self.ui={'X-Guard-UI':'1','X-CSRF-Token':r.json()['csrf_token']}
        return r
    def test_cookie_flags_and_me(self):
        r=self.login('admin','a'*32)
        cookie=r.headers['set-cookie'].lower()
        for flag in ('httponly','secure','samesite=strict'):self.assertIn(flag,cookie)
        self.assertTrue(self.client.get('/api/me').json()['is_admin'])
    def test_anonymous_cannot_read_or_export(self):
        self.client.cookies.clear()
        for path in ('/api/me','/api/settings','/api/events','/api/events/export'):
            self.assertEqual(self.client.get(path).status_code,401)
    def test_bad_login_no_secret_echo(self):
        r=self.client.post('/api/login',json={'username':'admin','password':'wrong-password'},headers={'X-Guard-UI':'1'})
        self.assertEqual(r.status_code,401);self.assertNotIn('wrong-password',r.text)
    def test_login_event_once_not_per_api_request(self):
        self.login('officer1','c'*32)
        for _ in range(3):self.client.get('/api/settings');self.client.get('/api/me')
        rows=self.client.get('/api/events?decision=AUTH&username=officer1').json()
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['code'],'LOGIN_SUCCESS')
    def test_operator_cannot_change_any_connection_field(self):
        self.login('officer1','c'*32)
        for key in guard.ADMIN_FIELDS:
            self.assertEqual(self.client.post('/api/settings',json={key:'value'},headers=self.ui).status_code,403,key)
    def test_operator_can_edit_policy_without_touching_connections(self):
        self.client.post('/api/settings',json={'llm_model':'kept-model'},headers=self.ui)
        self.login('officer1','c'*32)
        r=self.client.post('/api/settings',json={'blocked_terms':['test-project'],'block_email':False},headers=self.ui)
        self.assertEqual(r.status_code,200,r.text)
        settings=self.client.get('/api/settings').json()
        self.assertEqual(settings['llm_model'],'kept-model');self.assertFalse(settings['block_email'])
    def test_admin_can_change_region(self):
        r=self.client.post('/api/settings',json={'region':'213'},headers=self.ui)
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(self.client.get('/api/settings').json()['region'],'213')
    def test_csrf_required(self):
        self.assertEqual(self.client.post('/api/events/clear',json={},headers={'X-Guard-UI':'1'}).status_code,403)
    def test_logout_revokes_session(self):
        self.assertEqual(self.client.post('/api/logout',json={},headers=self.ui).status_code,200)
        self.assertEqual(self.client.get('/api/events').status_code,401)
    def test_operator_can_export_filter(self):
        self.login('officer1','c'*32)
        r=self.client.get('/api/events/export?decision=AUTH&username=officer1')
        self.assertEqual(r.status_code,200,r.text[:100])
        self.assertTrue(r.content.startswith(b'PK'))
        self.assertIn('spreadsheetml',r.headers['content-type'])
    def test_bad_filter_rejected(self):
        self.assertEqual(self.client.get('/api/events/export?decision=INVALID').status_code,422)
        self.assertEqual(self.client.get('/api/events?date_from=bad-date').status_code,422)
    def test_rule_blocks_without_any_external_call(self):
        self.body['query']['queryText']='synthetic@example.com'
        with patch.object(guard,'classify',new_callable=AsyncMock) as model,patch.object(guard,'forward_yandex',new_callable=AsyncMock) as yandex:
            r=self.client.post('/v2/web/search',headers=self.headers,json=self.body)
            self.assertEqual(r.status_code,403);model.assert_not_awaited();yandex.assert_not_awaited()
    def test_model_failure_blocks(self):
        with patch.object(guard,'classify',new_callable=AsyncMock,return_value=('BLOCK','MODEL_ERROR')),patch.object(guard,'forward_yandex',new_callable=AsyncMock) as yandex:
            r=self.client.post('/v2/web/search',headers=self.headers,json=self.body)
            self.assertEqual(r.status_code,403);yandex.assert_not_awaited()
    def test_allow_without_folder(self):
        self.s.folder_id=''
        with patch.object(guard,'read_settings',return_value=self.s),patch.object(guard,'classify',new_callable=AsyncMock,return_value=('ALLOW','MODEL_ALLOW')),patch.object(guard,'forward_yandex',new_callable=AsyncMock,return_value={'rawData':'test'}) as yandex:
            r=self.client.post('/v2/web/search',headers=self.headers,json=self.body)
            self.assertEqual(r.status_code,200,r.text)
            self.assertNotIn('folderId',yandex.await_args.args[0])
    def test_no_keys_in_ui(self):
        with patch.object(guard,'read_settings',return_value=self.s):
            r=self.client.get('/api/settings')
            self.assertNotIn('TEST_ONLY_KEY',r.text);self.assertEqual(r.json()['yandex_key'],'')
    def test_test_query_records_operator(self):
        self.login('officer1','c'*32)
        with patch.object(guard,'classify',new_callable=AsyncMock,return_value=('ALLOW','MODEL_ALLOW')),patch.object(guard,'forward_yandex',new_callable=AsyncMock) as yandex:
            r=self.client.post('/api/test',json={'query':'PostgreSQL'},headers=self.ui)
            self.assertEqual(r.status_code,200,r.text);yandex.assert_not_awaited()
        rows=self.client.get('/api/events?decision=ALLOW&username=officer1').json()
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['origin'],'test')
    def test_machine_auth_separate_from_ui(self):
        self.assertEqual(self.client.post('/v2/web/search',json=self.body).status_code,401)
    def test_unknown_and_duplicate_fields_rejected(self):
        self.body['extra']='synthetic@example.com'
        self.assertEqual(self.client.post('/v2/web/search',headers=self.headers,json=self.body).status_code,422)
        raw='{"query":{"queryText":"safe","queryText":"synthetic@example.com"}}'
        self.assertEqual(self.client.post('/v2/web/search',headers={**self.headers,'Content-Type':'application/json'},content=raw).status_code,422)

if __name__=='__main__':unittest.main(verbosity=2)
