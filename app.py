"""Local OAuth + Pipe sample. Run a single process on localhost:3000."""
import base64
import hashlib
import json
import logging
import math
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from media import fetch_media, valid_media
from flask import Response, Flask, g, jsonify, redirect, request, send_file
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

ORIGIN = 'http://localhost:3000'
CALLBACK = ORIGIN + '/callback'
TOKEN_URL = 'https://oauth.deezer.com/token'
PIPE_URL = 'https://pipe.deezer.com/api'
COOKIE = 'unaite_sample'
SESSION_TTL = 12 * 3600
MAX_RESPONSE = 1024 * 1024
MAX_SESSIONS = 1000


class UpstreamError(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def upstream_transport(url, payload, headers):
    """Fixed HTTPS destinations, no redirects, bounded reads and a timeout."""
    if url not in (TOKEN_URL, PIPE_URL):
        raise UpstreamError()
    req = Request(url, data=json.dumps(payload).encode(), method='POST',
                  headers={'Content-Type': 'application/json', 'Accept': 'application/json', **headers})
    try:
        with build_opener(NoRedirect()).open(req, timeout=20) as response:
            return response.status, response.read(MAX_RESPONSE + 1)
    except HTTPError as exc:
        exc.close()
        raise UpstreamError() from None
    except Exception:
        raise UpstreamError() from None


def load_env(path):
    """Read simple KEY=VALUE lines. Existing process variables take precedence."""
    if not path.is_file():
        return
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        key, value = key.strip(), value.strip()
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key):
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        os.environ.setdefault(key, value)


@dataclass
class Session:
    expires: float
    generation: int = 0
    csrf: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    access: str = ''
    refresh: str = ''
    token_expires: float = 0
    pending: dict | None = None
    lock: threading.RLock = field(default_factory=threading.RLock)


def create_app(config=None, *, transport=upstream_transport, media_transport=fetch_media, now=time.time, root=None):
    root = Path(root) if root is not None else Path(__file__).resolve().parent
    settings = os.environ if config is None else config
    client_id = settings.get('DEEZER_CLIENT_ID', '').strip()
    app_id = settings.get('DEEZER_APP_ID', '').strip()
    if client_id.startswith('YOUR_'):
        client_id = ''
    if app_id.startswith('YOUR_'):
        app_id = ''
    app = Flask(__name__, static_folder=None)
    app.config['MAX_CONTENT_LENGTH'] = 65536
    sessions = {}
    guard = threading.RLock()
    sdk = root / 'node_modules/@deezer/sdk-player/build/umd/index.js'

    def error(name, status):
        return jsonify(error=name), status

    def new_session():
        sid = secrets.token_urlsafe(32)
        session = Session(expires=now() + SESSION_TTL)
        with guard:
            if len(sessions) >= MAX_SESSIONS:
                return None
            sessions[sid] = session
        g.sid, g.session, g.cookie = sid, session, sid
        return session

    def active(session):
        with guard:
            return sessions.get(g.sid) is session and session.expires > now()

    def call(url, payload, headers=None):
        try:
            status, raw = transport(url, payload, headers or {})
            if not 200 <= status < 300 or len(raw) > MAX_RESPONSE:
                raise UpstreamError()
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise UpstreamError()
            return result
        except Exception:
            raise UpstreamError() from None

    def set_tokens(session, data):
        # OAuth refresh responses may omit a replacement refresh token.
        # Initial code exchange has no prior token, so omission still fails.
        access, refresh, expiry = data.get('access_token'), data.get('refresh_token', session.refresh), data.get('expires_in')
        if (not isinstance(access, str) or not access or not isinstance(refresh, str) or not refresh
                or isinstance(expiry, bool) or not isinstance(expiry, (int, float))
                or not math.isfinite(expiry) or expiry <= 0):
            raise UpstreamError()
        session.access, session.refresh = access, refresh
        session.token_expires = now() + expiry

    def ensure_token(session, force=False):
        if not active(session) or not session.access:
            return error('login_required', 401)
        if force or session.token_expires <= now() + 30:
            generation = session.generation
            try:
                data = call(TOKEN_URL, {'grant_type': 'refresh_token', 'client_id': client_id,
                                        'refresh_token': session.refresh})
                with guard:
                    if not active(session) or session.generation != generation:
                        return error('login_required', 401)
                    set_tokens(session, data)
            except UpstreamError:
                with guard:
                    if not active(session) or session.generation != generation:
                        return error('login_required', 401)
                    session.access = session.refresh = ''
                    session.token_expires = 0
                return error('refresh_failed', 401)
        return None

    @app.before_request
    def protect():
        if request.host != 'localhost:3000':
            return error('forbidden', 403)
        g.cookie = None
        g.sid = request.cookies.get(COOKIE, '')
        with guard:
            for sid in list(sessions):
                if sessions[sid].expires <= now():
                    del sessions[sid]
            g.session = sessions.get(g.sid)
        if request.method == 'POST':
            if request.headers.get('Origin') != ORIGIN or g.session is None:
                return error('forbidden', 403)
            request.get_data()  # Enforce the size cap even for bodyless endpoints.
            csrf = request.headers.get('X-CSRF-Token', '')
            if not csrf and request.mimetype == 'application/x-www-form-urlencoded':
                csrf = request.form.get('csrf', '')
            if not secrets.compare_digest(csrf.encode(), g.session.csrf.encode()):
                return error('forbidden', 403)
            # Cancel in-flight work before waiting for the session's network lock.
            # A new login supersedes both an older exchange and a pending refresh.
            if request.path in ('/login', '/logout'):
                with guard:
                    if not active(g.session):
                        return error('forbidden', 403)
                    g.session.generation += 1
                    g.generation = g.session.generation
                    g.session.pending = None
                    g.session.access = g.session.refresh = ''
                    g.session.token_expires = 0
                    if request.path == '/logout':
                        sessions.pop(g.sid, None)

    @app.after_request
    def response_headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer' if request.path == '/callback' else 'same-origin'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self' https://*.deezer.com https://*.dzcdn.net wss://live.deezer.com; "
            "media-src 'self' blob: https://*.deezer.com https://*.dzcdn.net; "
            "worker-src 'self' blob:; form-action 'self' https://oauth.deezer.com; "
            "frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        )
        if getattr(g, 'cookie', None):
            response.set_cookie(COOKIE, g.cookie, httponly=True, samesite='Lax',
                                path='/', max_age=SESSION_TTL)
        return response

    @app.errorhandler(RequestEntityTooLarge)
    def body_too_large(_exc):
        return error('body_too_large', 413)

    @app.errorhandler(BadRequest)
    def bad_request(_exc):
        return error('invalid_request', 400)

    @app.get('/')
    def index():
        return send_file(root / 'public/index.html')

    @app.get('/playground')
    def playground():
        return send_file(root / 'public/playground.html')

    @app.get('/playground.mjs')
    def playground_js():
        return send_file(root / 'public/playground.mjs', mimetype='text/javascript')

    @app.get('/playground.css')
    def playground_css():
        return send_file(root / 'public/playground.css', mimetype='text/css')

    @app.get('/app.js')
    def javascript():
        return send_file(root / 'public/app.js', mimetype='text/javascript')

    @app.get('/styles.css')
    def styles():
        return send_file(root / 'public/styles.css', mimetype='text/css')

    @app.get('/sdk-player.js')
    def player_sdk():
        if not sdk.is_file():
            return error('sdk_not_installed', 404)
        return send_file(sdk, mimetype='text/javascript')

    @app.get('/api/session')
    def session_info():
        session = g.session or new_session()
        if session is None:
            return error('session_capacity', 503)
        with session.lock:
            return jsonify(authenticated=bool(session.access), csrf=session.csrf, appId=app_id,
                           sdkAvailable=sdk.is_file(), configured=bool(client_id),
                           expiresAt=int(session.token_expires * 1000) if session.access else None)

    @app.post('/login')
    def login():
        if not client_id:
            return error('not_configured', 400)
        from urllib.parse import urlencode
        session = g.session
        with session.lock:
            if not active(session) or session.generation != g.generation:
                return error('forbidden', 403)
            verifier = secrets.token_urlsafe(64)
            state = secrets.token_urlsafe(32)
            session.pending = {'state': state, 'verifier': verifier, 'expires': now() + 600}
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
            return redirect('https://oauth.deezer.com/authorize?' + urlencode({
                'response_type': 'code', 'client_id': client_id, 'redirect_uri': CALLBACK, 'scope': 'all',
                'state': state, 'code_challenge': challenge, 'code_challenge_method': 'S256'}), code=303)

    @app.get('/callback')
    def callback():
        session = g.session
        if session is None or any(len(request.args.getlist(k)) != 1 or not request.args[k] for k in ('state', 'code')):
            return error('invalid_callback', 400)
        with session.lock:
            pending = session.pending
            if (not active(session) or not pending or pending['expires'] <= now()
                    or not secrets.compare_digest(pending['state'].encode(), request.args['state'].encode())):
                return error('invalid_callback', 400)
            session.pending = None  # Consume before the network call, including on failure.
            generation = session.generation
            try:
                data = call(TOKEN_URL, {'grant_type': 'authorization_code', 'client_id': client_id,
                                       'redirect_uri': CALLBACK, 'code': request.args['code'],
                                       'code_verifier': pending['verifier']})
                replacement = Session(expires=now() + SESSION_TTL)
                set_tokens(replacement, data)
            except UpstreamError:
                return error('upstream_failed', 502)
            with guard:
                if not active(session) or session.generation != generation:
                    return error('invalid_callback', 400)
                sessions.pop(g.sid, None)
                sid = secrets.token_urlsafe(32)
                sessions[sid] = replacement
                g.sid, g.session, g.cookie = sid, replacement, sid
            return redirect('/', code=303)

    @app.post('/api/token')
    @app.post('/api/refresh')
    @app.post('/api/pipe')
    def api():
        session = g.session
        with session.lock:
            failure = ensure_token(session, force=request.path == '/api/refresh')
            if failure is not None:
                return failure
            if request.path == '/api/refresh':
                return jsonify(refreshed=True)
            if request.path == '/api/token':
                return jsonify(access_token=session.access)
            body = request.get_json(silent=True)
            if (not isinstance(body, dict) or set(body) - {'query', 'variables'}
                    or not isinstance(body.get('query'), str) or not body['query'].strip()
                    or ('variables' in body and not isinstance(body['variables'], dict))):
                return error('invalid_request', 400)
            try:
                return jsonify(call(PIPE_URL, body, {'Authorization': 'Bearer ' + session.access}))
            except UpstreamError:
                return error('upstream_failed', 502)

    @app.post('/api/media')
    def media():
        session = g.session
        with session.lock:
            failure = ensure_token(session)
            if failure is not None:
                return failure
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or not valid_media(body.get('url'), body.get('range', '')):
            return error('invalid_media', 400)
        try:
            status, data, headers = media_transport(body['url'], body.get('range', ''))
            if not active(session):
                return error('login_required', 401)
            return Response(data, status=status, headers=headers)
        except Exception:
            return error('media_failed', 502)

    @app.post('/logout')
    def logout():
        # protect() has already revoked this session, even if a network call is pending.
        response = jsonify(loggedOut=True)
        response.delete_cookie(COOKIE, path='/', httponly=True, samesite='Lax')
        return response

    return app


if __name__ == '__main__':
    load_env(Path(__file__).resolve().parent / '.env')
    # Werkzeug access logs include the OAuth callback query; never log it.
    logging.getLogger('werkzeug').disabled = True
    create_app().run(host='127.0.0.1', port=3000, debug=False, use_reloader=False, threaded=True, load_dotenv=False)
