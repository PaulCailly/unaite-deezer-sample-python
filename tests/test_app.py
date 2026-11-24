import base64
import hashlib
import importlib.util
import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ORIGIN = 'http://localhost:3000'


class SampleTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('app'), 'The application must exist')
        from app import create_app
        self.now = 1000.0
        self.calls = []
        self.reply = (200, {'access_token': 'access-a', 'refresh_token': 'refresh-a', 'expires_in': 60})
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / 'public').mkdir()
        (self.root / 'public/index.html').write_text('hello')
        (self.root / '.env').write_text('SECRET=private')
        self.app = create_app({'DEEZER_CLIENT_ID': 'test-client', 'DEEZER_APP_ID': 'test-app'},
                              transport=self.transport, media_transport=self.media_transport, now=lambda: self.now, root=self.root)
        @self.app.before_request
        def observe_request():
            from flask import request
            if request.path == getattr(self, 'observed_path', None):
                self.request_seen.set()
        self.client = self.app.test_client()

    def test_playground_assets_are_reachable_without_exposing_private_files(self):
        for name in ['playground.html', 'playground.mjs', 'playground.css']:
            (self.root / 'public' / name).write_text('playground test fixture')
        for path in ['/playground', '/playground.mjs', '/playground.css']:
            response = self.client.get(path, base_url=ORIGIN)
            self.assertEqual(response.status_code, 200, path)
            self.assertIn('no-store', response.headers['Cache-Control'])
            response.close()
        self.assertEqual(self.client.get('/.env', base_url=ORIGIN).status_code, 404)

    def media_transport(self, url, byte_range):
        self.media_calls.append((url, byte_range))
        return 206, b'abc', {'Content-Type': 'audio/mpeg', 'Content-Range': 'bytes 0-2/100'}

    def test_media_relay_authentication_allowlist_and_ranges(self):
        self.media_calls = []
        url = 'https://cdnt-stream.dzcdn.net/media/1/1/a/audio.mp3?hdnea=test'
        self.assertEqual(self.post('/api/media', {'url': url}).status_code, 401)
        self.login()
        for bad in ['http://cdnt-stream.dzcdn.net/media/a.mp3?hdnea=x', 'https://localhost/media/a.mp3?hdnea=x',
                    'https://cdnt-stream.dzcdn.net.evil.test/media/a.mp3?hdnea=x', 'https://user@cdnt-stream.dzcdn.net/media/a.mp3?hdnea=x',
                    'https://cdnt-stream.dzcdn.net:8443/media/a.mp3?hdnea=x', 'https://cdnt-stream.dzcdn.net/private?hdnea=x']:
            self.assertEqual(self.post('/api/media', {'url': bad}).status_code, 400)
        self.assertEqual(self.post('/api/media', {'url': url, 'range': 'bytes=0-1,2-3'}).status_code, 400)
        self.assertEqual(self.media_calls, [])
        response = self.post('/api/media', {'url': url, 'range': 'bytes=0-2'})
        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.data, b'abc')
        self.assertEqual(response.headers['Content-Range'], 'bytes 0-2/100')
        self.assertEqual(len(self.media_calls), 1)

    def transport(self, url, payload, headers):
        self.calls.append((url, payload, headers))
        if hasattr(self, 'upstream_entered'):
            self.upstream_entered.set()
            if not self.upstream_release.wait(5):
                raise RuntimeError('Test transport was not released')
        status, data = self.reply
        return status, json.dumps(data).encode()

    def get(self, path, client=None):
        return (client or self.client).get(path, base_url=ORIGIN)

    def session(self, client=None):
        return self.get('/api/session', client).get_json()

    def post(self, path, data=None, client=None, csrf=None):
        client = client or self.client
        csrf = csrf or self.session(client)['csrf']
        return client.post(path, base_url=ORIGIN, json=data,
                           headers={'Origin': ORIGIN, 'X-CSRF-Token': csrf})

    def begin(self, client=None):
        response = self.post('/login', client=client)
        self.assertEqual(response.status_code, 303)
        return parse_qs(urlparse(response.location).query)

    def login(self, client=None):
        params = self.begin(client)
        response = self.get('/callback?state=' + params['state'][0] + '&code=one-use-code', client)
        self.assertEqual(response.status_code, 303)
        return params

    def test_login_pkce_and_callback_rotate_session_and_csrf(self):
        initial = self.session()
        cookie = self.client.get_cookie('unaite_sample')
        self.assertTrue(cookie.http_only)
        self.assertEqual(cookie.same_site, 'Lax')
        params = self.login()
        self.assertEqual(params['redirect_uri'], [ORIGIN + '/callback'])
        self.assertEqual(params['scope'], ['all'])
        self.assertEqual(params['code_challenge_method'], ['S256'])
        url, body, _ = self.calls[0]
        self.assertEqual(url, 'https://oauth.deezer.com/token')
        self.assertEqual(body['grant_type'], 'authorization_code')
        challenge = base64.urlsafe_b64encode(hashlib.sha256(body['code_verifier'].encode()).digest()).rstrip(b'=').decode()
        self.assertEqual(params['code_challenge'], [challenge])
        current = self.session()
        self.assertTrue(current['authenticated'])
        self.assertEqual(current['expiresAt'], 1060000)
        self.assertNotEqual(initial['csrf'], current['csrf'])
        self.assertNotEqual(cookie.value, self.client.get_cookie('unaite_sample').value)
        self.assertNotIn('access_token', current)
        self.assertEqual(self.post('/api/token').get_json(), {'access_token': 'access-a'})

    def test_callback_requires_own_cookie_and_one_time_state(self):
        params = self.begin()
        callback = '/callback?state=' + params['state'][0] + '&code=x'
        self.assertEqual(self.get(callback, self.app.test_client()).status_code, 400)
        self.assertEqual(self.get(callback).status_code, 303)
        self.assertEqual(self.get(callback).get_json(), {'error': 'invalid_callback'})
        self.assertEqual(len(self.calls), 1)

    def test_callback_rejects_missing_duplicates_wrong_and_expired_state(self):
        params = self.begin()
        state = params['state'][0]
        for query in ('', '?state=' + state, '?state=wrong&code=x',
                      '?state=' + state + '&state=' + state + '&code=x',
                      '?state=' + state + '&code=x&code=y'):
            self.assertEqual(self.get('/callback' + query).status_code, 400)
        self.now += 601
        self.assertEqual(self.get('/callback?state=' + state + '&code=x').status_code, 400)
        self.assertEqual(self.calls, [])

    def test_host_origin_and_csrf_are_enforced(self):
        self.assertEqual(self.client.get('/api/session', base_url='http://evil.test:3000').status_code, 403)
        csrf = self.session()['csrf']
        for headers in ({}, {'Origin': ORIGIN}, {'Origin': 'http://evil.test', 'X-CSRF-Token': csrf},
                        {'Origin': ORIGIN, 'X-CSRF-Token': 'wrong'}):
            self.assertEqual(self.client.post('/login', base_url=ORIGIN, headers=headers).status_code, 403)
        self.assertEqual(self.client.post('/login', base_url=ORIGIN, data={'csrf': csrf},
                                         headers={'Origin': ORIGIN}).status_code, 303)

    def test_session_expiry_and_missing_configuration(self):
        from app import create_app
        empty = create_app({}, transport=self.transport, media_transport=self.media_transport, now=lambda: self.now, root=self.root).test_client()
        self.assertFalse(self.session(empty)['configured'])
        self.assertEqual(self.post('/login', client=empty).status_code, 400)
        self.login()
        old = self.session()['csrf']
        self.now += 12 * 3600 + 1
        self.assertFalse(self.session()['authenticated'])
        self.assertNotEqual(old, self.session()['csrf'])
        self.assertEqual(self.post('/api/token').status_code, 401)

    def test_refresh_rotates_token_and_automatic_refresh_uses_it(self):
        self.login()
        self.reply = (200, {'access_token': 'access-b', 'refresh_token': 'refresh-b', 'expires_in': 60})
        self.assertEqual(self.post('/api/refresh').get_json(), {'refreshed': True})
        self.assertEqual(self.calls[-1][1]['refresh_token'], 'refresh-a')
        self.now += 31
        self.reply = (200, {'access_token': 'access-c', 'refresh_token': 'refresh-c', 'expires_in': 60})
        self.assertEqual(self.post('/api/token').get_json(), {'access_token': 'access-c'})
        self.assertEqual(self.calls[-1][1]['refresh_token'], 'refresh-b')

    def test_refresh_failure_invalidates_only_own_session_and_hides_errors(self):
        other = self.app.test_client()
        self.login()
        self.login(other)
        self.reply = (400, {'error': 'secret upstream details'})
        response = self.post('/api/refresh')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json(), {'error': 'refresh_failed'})
        self.assertFalse(self.session()['authenticated'])
        self.assertTrue(self.session(other)['authenticated'])
        self.assertEqual(self.post('/api/token').status_code, 401)

    def test_pipe_preserves_graphql_errors_and_restricts_payload(self):
        self.assertEqual(self.post('/api/pipe', {'query': '{ me { id } }'}).status_code, 401)
        self.login()
        self.reply = (200, {'data': None, 'errors': [{'message': 'field unavailable'}]})
        response = self.post('/api/pipe', {'query': '{ me { id } }', 'variables': {}})
        self.assertEqual(response.get_json(), self.reply[1])
        self.assertEqual(self.calls[-1][0], 'https://pipe.deezer.com/api')
        self.assertEqual(self.calls[-1][2]['Authorization'], 'Bearer access-a')
        for body in ({'query': 'x', 'url': 'https://evil.test'}, {'query': 1}, {'query': 'x', 'variables': []}):
            self.assertEqual(self.post('/api/pipe', body).status_code, 400)
        self.assertEqual(self.post('/api/pipe', {'query': 'x' * 65536}).status_code, 413)

    def test_upstream_redirect_and_huge_reply_are_rejected(self):
        self.login()
        self.reply = (302, {'access_token': 'secret'})
        self.assertEqual(self.post('/api/pipe', {'query': 'x'}).get_json(), {'error': 'upstream_failed'})
        self.reply = (200, {'data': 'x' * (1024 * 1024)})
        self.assertEqual(self.post('/api/pipe', {'query': 'x'}).status_code, 502)

    def test_static_allowlist_logout_and_no_cors(self):
        with self.get('/') as response:
            self.assertEqual(response.data, b'hello')
        for path in ('/.env', '/app.py', '/node_modules/x', '/public/../.env'):
            self.assertEqual(self.get(path).status_code, 404)
        self.assertNotIn('Access-Control-Allow-Origin', self.get('/api/session').headers)
        self.login()
        self.assertEqual(self.post('/logout').status_code, 200)
        self.assertIsNone(self.client.get_cookie('unaite_sample'))
        self.assertFalse(self.session()['authenticated'])

    def test_unicode_security_inputs_reject_without_server_error(self):
        self.begin()
        self.assertEqual(self.post('/api/token', csrf='é').status_code, 403)
        self.assertEqual(self.get('/callback?state=%C3%A9&code=x').status_code, 400)

    def test_body_limit_applies_even_when_endpoint_ignores_body(self):
        self.login()
        self.assertEqual(self.post('/api/token', {'padding': 'x' * 65536}).status_code, 413)

    def test_concurrent_requests_share_one_automatic_refresh(self):
        self.login()
        self.now += 31
        cookie = self.client.get_cookie('unaite_sample').value
        csrf = self.session()['csrf']
        barrier = threading.Barrier(2)
        self.reply = (200, {'access_token': 'new-access', 'refresh_token': 'new-refresh', 'expires_in': 3600})

        def token_request():
            client = self.app.test_client()
            client.set_cookie('unaite_sample', cookie)
            barrier.wait(timeout=5)
            return self.post('/api/token', client=client, csrf=csrf).get_json()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: token_request(), range(2)))
        self.assertEqual(results, [{'access_token': 'new-access'}] * 2)
        self.assertEqual(len(self.calls), 2)  # Code exchange + one refresh.

    def test_failed_callback_is_consumed_and_malformed_tokens_not_accepted(self):
        state = self.begin()['state'][0]
        self.reply = (200, {'access_token': 'bad', 'refresh_token': 'bad', 'expires_in': -1})
        url = '/callback?state=' + state + '&code=x'
        self.assertEqual(self.get(url).status_code, 502)
        self.assertEqual(self.get(url).status_code, 400)
        self.assertFalse(self.session()['authenticated'])

    def test_refresh_without_replacement_keeps_previous_refresh_token(self):
        self.login()
        self.reply = (200, {'access_token': 'access-b', 'expires_in': 60})
        self.assertEqual(self.post('/api/refresh').get_json(), {'refreshed': True})
        self.now += 31
        self.reply = (200, {'access_token': 'access-c', 'expires_in': 60})
        self.assertEqual(self.post('/api/token').get_json(), {'access_token': 'access-c'})
        self.assertEqual(self.calls[-1][1]['refresh_token'], 'refresh-a')

    def test_initial_token_response_requires_refresh_token(self):
        state = self.begin()['state'][0]
        self.reply = (200, {'access_token': 'access-a', 'expires_in': 3600})
        self.assertEqual(self.get('/callback?state=' + state + '&code=x').status_code, 502)
        self.assertFalse(self.session()['authenticated'])

    def test_placeholder_client_id_is_not_configured(self):
        from app import create_app
        client = create_app({'DEEZER_CLIENT_ID': 'YOUR_CLIENT_ID'}, root=self.root).test_client()
        self.assertFalse(self.session(client)['configured'])
        self.assertEqual(self.post('/login', client=client).status_code, 400)

    def test_session_capacity_preserves_existing_sessions_and_recovers(self):
        initial = self.session()
        for _ in range(999):
            self.assertEqual(self.get('/api/session', self.app.test_client()).status_code, 200)
        blocked = self.app.test_client()
        self.assertEqual(self.get('/api/session', blocked).status_code, 503)
        self.assertEqual(self.session()['csrf'], initial['csrf'])
        self.assertEqual(self.post('/logout').status_code, 200)
        self.assertEqual(self.get('/api/session', blocked).status_code, 200)
        self.now += 12 * 3600 + 1
        self.assertEqual(self.get('/api/session', self.app.test_client()).status_code, 200)

    def test_csp_allows_local_frontend_and_deezer_media_only(self):
        policy = self.get('/api/session').headers.get('Content-Security-Policy', '')
        for directive in ("script-src 'self'", "style-src 'self'", "frame-ancestors 'none'",
                          "base-uri 'none'", "form-action 'self' https://oauth.deezer.com",
                          "connect-src 'self' https://*.deezer.com https://*.dzcdn.net wss://live.deezer.com",
                          "media-src 'self' blob: https://*.deezer.com https://*.dzcdn.net",
                          "worker-src 'self' blob:"):
            self.assertIn(directive, policy.split('; '))
        self.assertNotIn('unsafe-inline', policy)
        self.assertNotIn('unsafe-eval', policy)

    def suspend_upstream(self):
        self.upstream_entered = threading.Event()
        self.upstream_release = threading.Event()
        self.addCleanup(self.upstream_release.set)

    def concurrent_client(self):
        client = self.app.test_client()
        client.set_cookie('unaite_sample', self.client.get_cookie('unaite_sample').value)
        return client

    def test_logout_during_callback_cannot_resurrect_session(self):
        state = self.begin()['state'][0]
        csrf = self.session()['csrf']
        other = self.concurrent_client()
        seen = threading.Event()
        self.observed_path, self.request_seen = '/logout', seen
        self.suspend_upstream()
        with ThreadPoolExecutor(max_workers=2) as pool:
            callback = pool.submit(self.get, '/callback?state=' + state + '&code=x')
            self.assertTrue(self.upstream_entered.wait(5))
            logout = pool.submit(self.post, '/logout', client=other, csrf=csrf)
            self.assertTrue(seen.wait(5))
            self.upstream_release.set()
            self.assertEqual(logout.result().status_code, 200)
            self.assertEqual(callback.result().status_code, 400)
        self.assertFalse(self.session()['authenticated'])

    def test_new_login_during_callback_supersedes_old_exchange(self):
        state = self.begin()['state'][0]
        csrf = self.session()['csrf']
        other = self.concurrent_client()
        seen = threading.Event()
        self.observed_path, self.request_seen = '/login', seen
        self.suspend_upstream()
        with ThreadPoolExecutor(max_workers=2) as pool:
            callback = pool.submit(self.get, '/callback?state=' + state + '&code=x')
            self.assertTrue(self.upstream_entered.wait(5))
            login = pool.submit(self.post, '/login', client=other, csrf=csrf)
            self.assertTrue(seen.wait(5))
            self.upstream_release.set()
            self.assertEqual(callback.result().status_code, 400)
            new_state = parse_qs(urlparse(login.result().location).query)['state'][0]
        self.assertFalse(self.session(other)['authenticated'])
        self.assertEqual(self.get('/callback?state=' + new_state + '&code=new', other).status_code, 303)

    def test_expiry_during_callback_prevents_session_rotation(self):
        state = self.begin()['state'][0]
        self.suspend_upstream()
        with ThreadPoolExecutor(max_workers=1) as pool:
            callback = pool.submit(self.get, '/callback?state=' + state + '&code=x')
            self.assertTrue(self.upstream_entered.wait(5))
            self.now += 12 * 3600 + 1
            self.upstream_release.set()
            self.assertEqual(callback.result().status_code, 400)
        self.assertFalse(self.session()['authenticated'])

    def test_logout_during_refresh_prevents_returning_access_token(self):
        self.login()
        csrf = self.session()['csrf']
        other = self.concurrent_client()
        self.now += 31
        seen = threading.Event()
        self.observed_path, self.request_seen = '/logout', seen
        self.suspend_upstream()
        with ThreadPoolExecutor(max_workers=2) as pool:
            token = pool.submit(self.post, '/api/token', csrf=csrf)
            self.assertTrue(self.upstream_entered.wait(5))
            logout = pool.submit(self.post, '/logout', client=other, csrf=csrf)
            self.assertTrue(seen.wait(5))
            self.upstream_release.set()
            self.assertEqual(logout.result().status_code, 200)
            self.assertEqual(token.result().status_code, 401)
        self.assertFalse(self.session()['authenticated'])


if __name__ == '__main__':
    unittest.main()
