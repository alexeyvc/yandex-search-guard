import unittest
import test_guard as baseline

class Patch031HTTPTests(unittest.TestCase):
    setUp = baseline.GuardTests.setUp
    tearDown = baseline.GuardTests.tearDown
    login = baseline.GuardTests.login

    def test_end_date_returns_422(self):
        for path in ('/api/events', '/api/events/export'):
            r = self.client.get(path + '?date_to=9999-12-31')
            self.assertEqual(r.status_code, 422, r.text[:100])

    def test_folder_limit_at_save(self):
        for value in ('', 'x' * 50):
            r = self.client.post('/api/settings', json={'folder_id': value}, headers=self.ui)
            self.assertEqual(r.status_code, 200, r.text)
        r = self.client.post('/api/settings', json={'folder_id': 'x' * 51}, headers=self.ui)
        self.assertEqual(r.status_code, 422, r.text)
        self.assertEqual(self.client.get('/api/settings').json()['folder_id'], 'x' * 50)
