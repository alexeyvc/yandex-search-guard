import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

_tmp = tempfile.TemporaryDirectory()
os.environ.update(DATA_DIR=_tmp.name, ADMIN_PASSWORD='a'*32, SEARCH_TOKEN='b'*32)
import app as guard
from fastapi.testclient import TestClient

class GuardTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(guard.app, raise_server_exceptions=False)
        self.auth = ('admin','a'*32)
        self.headers = {'Authorization':'Api-Key '+'b'*32}
        self.ui = {'X-Guard-UI':'1'}
        self.s = guard.Settings(llm_model='local-classifier',yandex_key='REAL_SECRET',folder_id='server-folder')
        self.body = {'query':{'queryText':'PostgreSQL replication','searchType':'SEARCH_TYPE_RU'},'responseFormat':'FORMAT_XML'}

    def test_auth(self):
        self.assertEqual(self.client.get('/').status_code,401)
        self.assertEqual(self.client.post('/v2/web/search',json=self.body).status_code,401)

    def test_rule_blocks_without_any_external_call(self):
        self.body['query']['queryText']='private@example.com'
        with patch.object(guard,'classify',new_callable=AsyncMock) as model, patch.object(guard,'forward_yandex',new_callable=AsyncMock) as yandex:
            r=self.client.post('/v2/web/search',headers=self.headers,json=self.body)
            self.assertEqual(r.status_code,403)
            self.assertEqual(r.headers['x-guard-code'],'EMAIL')
            model.assert_not_awaited(); yandex.assert_not_awaited()

    def test_model_failure_blocks(self):
        with patch.object(guard,'classify',new_callable=AsyncMock,return_value=('BLOCK','MODEL_ERROR')), patch.object(guard,'forward_yandex',new_callable=AsyncMock) as yandex:
            r=self.client.post('/v2/web/search',headers=self.headers,json=self.body)
            self.assertEqual(r.status_code,403)
            yandex.assert_not_awaited()

    def test_allow_preserves_yandex_response(self):
        expected={'rawData':'PHlhbmRleHNlYXJjaC8+'}
        with patch.object(guard,'read_settings',return_value=self.s), patch.object(guard,'classify',new_callable=AsyncMock,return_value=('ALLOW','MODEL_ALLOW')), patch.object(guard,'forward_yandex',new_callable=AsyncMock,return_value=expected) as yandex:
            r=self.client.post('/v2/web/search',headers=self.headers,json=self.body)
            self.assertEqual(r.status_code,200)
            self.assertEqual(r.json(),expected)
            self.assertEqual(yandex.await_args.args[0]['folderId'],'server-folder')

    def test_no_keys_in_ui(self):
        with patch.object(guard,'read_settings',return_value=self.s):
            r=self.client.get('/api/settings',auth=self.auth)
            self.assertNotIn('REAL_SECRET',r.text)
            self.assertEqual(r.json()['yandex_key'],'')

    def test_test_mode_never_yandex(self):
        with patch.object(guard,'classify',new_callable=AsyncMock,return_value=('ALLOW','MODEL_ALLOW')),patch.object(guard,'forward_yandex',new_callable=AsyncMock) as yandex:
            r=self.client.post('/api/test',auth=self.auth,headers=self.ui,json={'query':'PostgreSQL'})
            self.assertEqual(r.json()['decision'],'ALLOW')
            yandex.assert_not_awaited()

    def test_client_metadata_not_forwarded(self):
        self.body.update(folderId='attacker-folder',userAgent='private@example.com')
        result=guard.build_yandex_body(self.body,'PostgreSQL',self.s)
        self.assertEqual(result['folderId'],'server-folder')
        self.assertNotIn('userAgent',result)

    def test_unknown_fields_rejected(self):
        self.body['extra']='private@example.com'
        with patch.object(guard,'forward_yandex',new_callable=AsyncMock) as yandex:
            r=self.client.post('/v2/web/search',headers=self.headers,json=self.body)
            self.assertEqual(r.status_code,422)
            self.assertNotIn('private@example.com',r.text)
            yandex.assert_not_awaited()

    def test_duplicate_query_rejected(self):
        raw='{"query":{"queryText":"safe","queryText":"private@example.com"}}'
        r=self.client.post('/v2/web/search',headers={**self.headers,'Content-Type':'application/json'},content=raw)
        self.assertEqual(r.status_code,422)
        self.assertNotIn('private@example.com',r.text)

    def test_invalid_parameters_never_forwarded(self):
        self.body['query']['familyMode']='private@example.com'
        with patch.object(guard,'read_settings',return_value=self.s),patch.object(guard,'classify',new_callable=AsyncMock,return_value=('ALLOW','MODEL_ALLOW')),patch.object(guard,'forward_yandex',new_callable=AsyncMock) as yandex:
            r=self.client.post('/v2/web/search',headers=self.headers,json=self.body)
            self.assertEqual(r.status_code,422)
            yandex.assert_not_awaited()

    def test_csrf_header(self):
        self.assertEqual(self.client.post('/api/events/clear',auth=self.auth,json={}).status_code,403)

    def test_no_model(self):
        with patch.object(guard,'read_settings',return_value=guard.Settings()),patch.object(guard,'forward_yandex',new_callable=AsyncMock) as yandex:
            r=self.client.post('/v2/web/search',headers=self.headers,json=self.body)
            self.assertEqual(r.headers['x-guard-code'],'MODEL_NOT_CONFIGURED')
            yandex.assert_not_awaited()

if __name__=='__main__':
    unittest.main(verbosity=2)
