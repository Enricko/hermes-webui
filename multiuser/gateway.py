"""One browser origin; server sessions select physically isolated WebUI runtimes."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import http.cookies
import json
import logging
import mimetypes
import os
from pathlib import Path
import secrets
import sqlite3
from urllib.parse import urlsplit

import aiohttp
from aiohttp import web

from multiuser.broker import Brokers
from multiuser.settings import Settings
from multiuser.store import LoginDenied, PolicyError, RateLimited

SOURCE = Path(__file__).resolve().parent.parent
ASSETS = Path(__file__).resolve().parent / 'static'
COOKIE = 'hmu_session'
CSRF = 'X-Hermes-CSRF-Token'
HOP_HEADERS = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
               'te', 'trailer', 'transfer-encoding', 'upgrade', 'content-length',
               'set-cookie', 'service-worker-allowed', 'content-security-policy',
               'content-security-policy-report-only', 'clear-site-data'}
UNSAFE = {'POST', 'PUT', 'PATCH', 'DELETE'}
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
       "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
       "font-src 'self' data: https://fonts.gstatic.com https://cdn.jsdelivr.net; "
       "img-src 'self' data: blob: https:; media-src 'self' blob: data:; "
       "connect-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
       "frame-src 'self' blob:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; worker-src 'self'")


def json_response(value, *, status=200):
    return web.json_response(value, status=status, headers={'Cache-Control': 'no-store'})


async def object_body(request, allowed):
    if request.content_length is not None and request.content_length > 2 * 1024 * 1024:
        raise web.HTTPRequestEntityTooLarge(max_size=2 * 1024 * 1024, actual_size=request.content_length)
    data = bytearray()
    async for part in request.content.iter_chunked(65536):
        data.extend(part)
        if len(data) > 2 * 1024 * 1024:
            raise web.HTTPRequestEntityTooLarge(max_size=2 * 1024 * 1024, actual_size=len(data))
    value = json.loads(data)
    if not isinstance(value, dict) or set(value) - set(allowed):
        raise PolicyError('Unsupported request fields')
    return value


class Gateway:
    def __init__(self, settings):
        self.settings = settings.validate()
        self.store = settings.store()
        self.brokers = Brokers(settings)
        self.sessions = {}
        self.auth_slots = asyncio.Semaphore(4)
        digest = hashlib.sha256()
        for root in (SOURCE / 'static', ASSETS):
            for path in sorted(root.rglob('*')):
                if path.is_file() and path.suffix in ('.html', '.js', '.css'):
                    digest.update(path.read_bytes())
        self.version = 'mu-' + digest.hexdigest()[:16]

    def principal(self, request):
        return self.store.session(request.cookies.get(COOKIE, ''))

    def require(self, request, *, admin=False):
        session = self.principal(request)
        if session is None:
            raise web.HTTPUnauthorized(text='Authentication required')
        if admin and session.role != 'admin':
            raise web.HTTPForbidden(text='Administrator role required')
        if request.method in ('GET', 'HEAD') and request.path.startswith(('/api/', '/multiuser/api/')):
            # Upstream retains a few side-effect GETs (notably legacy cancel).
            # Fetch metadata covers EventSource, which cannot set custom headers;
            # native clients send the session-bound token on private API reads.
            origin = request.headers.get('Origin')
            same_origin = request.headers.get('Sec-Fetch-Site') == 'same-origin'
            token_matches = secrets.compare_digest(request.headers.get(CSRF, ''), session.csrf)
            if (origin is not None and origin != self.settings.origin) or not (same_origin or token_matches):
                raise web.HTTPForbidden(text='Private API origin/CSRF check failed')
        return session

    def check_origin(self, request):
        # No client-supplied identity/proxy headers are trusted. Configure the
        # public HTTPS origin explicitly; the TLS proxy may still connect locally.
        if request.headers.get('Origin') != self.settings.origin or request.headers.get('Sec-Fetch-Site') == 'cross-site':
            raise web.HTTPForbidden(text='Origin check failed')

    def check_csrf(self, request, session):
        self.check_origin(request)
        if not secrets.compare_digest(request.headers.get(CSRF, ''), session.csrf):
            raise web.HTTPForbidden(text='CSRF check failed')

    async def start(self, _app):
        if not self.settings.database.is_file():
            raise PolicyError('Initialize multi-user state explicitly before starting the gateway')
        if sqlite3.sqlite_version_info < (3, 51, 3):
            raise PolicyError('Use SQLite >=3.51.3 (the upstream WAL-reset fix) for the control plane')
        await self.brokers.start()

    async def close(self, _app):
        for session in self.sessions.values():
            await session.close()
        await self.brokers.close()

    @web.middleware
    async def boundary(self, request, handler):
        try:
            if request.host != urlsplit(self.settings.origin).netloc:
                raise web.HTTPBadRequest(text='Unexpected Host')
            if request.method in UNSAFE:
                if request.path == '/api/auth/login':
                    self.check_origin(request)
                else:
                    self.check_csrf(request, self.require(request))
            response = await handler(request)
        except RateLimited:
            response = json_response({'error': 'Too many login attempts; try again later'}, status=429)
        except LoginDenied:
            response = json_response({'error': 'Invalid username or password'}, status=401)
        except (PolicyError, ValueError, KeyError, TypeError):
            response = json_response({'error': 'Request refused: invalid fields or account policy'}, status=400)
        except sqlite3.IntegrityError:
            response = json_response({'error': 'Resource name or reference is unavailable'}, status=409)
        except web.HTTPException as exc:
            response = (web.Response(status=exc.status, headers=dict(exc.headers)) if 300 <= exc.status < 400
                        else json_response({'error': exc.reason}, status=exc.status))
        except Exception as exc:
            logging.error('Multi-user request failed: %s', type(exc).__name__)
            response = json_response({'error': 'Request failed'}, status=500)
        # Stream headers are assigned before prepare() inside proxy().
        if not response.prepared:
            self.security_headers(response)
        return response

    @staticmethod
    def security_headers(response):
        response.headers.setdefault('Content-Security-Policy', CSP)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['X-Frame-Options'] = 'DENY'

    async def login_page(self, request):
        return web.Response(text=(ASSETS / 'login.html').read_text(), content_type='text/html',
                            headers={'Cache-Control': 'no-store'})

    async def login(self, request):
        body = await object_body(request, {'username', 'password'})
        if self.auth_slots.locked():
            raise RateLimited('Authentication is busy')
        async with self.auth_slots:
            token, session = await asyncio.to_thread(self.store.login, body.get('username'), body.get('password'), request.remote or 'unknown')
        old = self.principal(request)
        if old:
            self.store.logout(old)
        response = json_response({'ok': True, 'user': session.public()})
        response.set_cookie(COOKIE, token, max_age=self.settings.session_ttl, httponly=True,
                            secure=self.settings.secure, samesite='Strict', path='/')
        response.del_cookie('hermes_profile', path='/')
        response.headers['Clear-Site-Data'] = '"cache", "storage"'
        return response

    async def logout(self, request):
        self.store.logout(self.require(request))
        response = json_response({'ok': True})
        response.del_cookie(COOKIE, path='/')
        response.del_cookie('hermes_profile', path='/')
        response.headers['Clear-Site-Data'] = '"cache", "storage"'
        return response

    async def auth_status(self, request):
        session = self.principal(request)
        if session:
            self.require(request)
        return json_response({'auth_enabled': True, 'authenticated': session is not None,
                              'csrf_token': session.csrf if session else None,
                              'multiuser': True, 'username': session.username if session else None})

    async def me(self, request):
        session = self.require(request)
        runtime = self.store.runtime(session.user_id)
        return json_response({**session.public(), 'runtime': {
            'state': runtime['state'] if runtime else 'pending',
            'message': runtime['error'] if runtime else ''}})

    async def users(self, request):
        actor = self.require(request, admin=True)
        if request.method in ('GET', 'HEAD'):
            users = self.store.users()
            for user in users:
                runtime = self.store.runtime(user['id'])
                user['runtime_state'] = runtime['state'] if runtime else 'pending'
            return json_response({'users': users})
        body = await object_body(request, {'username', 'password', 'role', 'template_id'})
        user = await asyncio.to_thread(self.store.create_user, body['username'], body['password'],
                    role=body.get('role', 'user'), template_id=body.get('template_id'), actor=actor.user_id)
        return json_response({'user': user}, status=201)

    async def update_user(self, request):
        actor = self.require(request, admin=True)
        body = await object_body(request, {'role', 'enabled', 'password', 'template_id'})
        changes = {k: v for k, v in body.items() if k != 'template_id'}
        if 'template_id' in body:
            changes.update(template_id=body['template_id'], assign_template=True)
        user = await asyncio.to_thread(self.store.update_user, request.match_info['uid'], actor=actor.user_id, **changes)
        return json_response({'user': user})

    async def providers(self, request):
        self.require(request, admin=True)
        if request.method in ('GET', 'HEAD'):
            return json_response({'providers': self.store.providers()})
        body = await object_body(request, {'id', 'name', 'base_url', 'secret', 'enabled'})
        pid = self.store.put_provider(body['name'], body['base_url'], body.get('secret'),
                                     provider_id=body.get('id'), enabled=body.get('enabled', True))
        return json_response({'id': pid})

    async def templates(self, request):
        self.require(request, admin=True)
        if request.method in ('GET', 'HEAD'):
            return json_response({'templates': self.store.templates()})
        body = await object_body(request, {'id', 'name', 'document', 'enabled'})
        tid = self.store.put_template(body['name'], body['document'], template_id=body.get('id'), enabled=body.get('enabled', True))
        return json_response({'id': tid})

    async def tools(self, request):
        principal = self.require(request)
        if request.method in ('GET', 'HEAD'):
            tools = self.store.tools(source=principal.role == 'admin')
            if principal.role != 'admin':
                allowed = set(self.store.template(principal.template_id)['document']['tools']) if principal.template_id else set()
                tools = [tool for tool in tools if tool['id'] in allowed and tool['enabled']]
            return json_response({'tools': tools})
        self.require(request, admin=True)
        body = await object_body(request, {'id', 'name', 'description', 'filename', 'content', 'enabled'})
        tid = self.store.put_tool(body['name'], body['description'], body['filename'], body['content'],
                                 tool_id=body.get('id'), enabled=body.get('enabled', True))
        return json_response({'id': tid})

    async def index(self, request):
        session = self.principal(request)
        if session is None:
            raise web.HTTPFound('/login')
        html = (SOURCE / 'static/index.html').read_text()
        # Upstream assets/API helpers use relative URLs; deep account/session
        # routes must resolve them against the same trusted origin root.
        html = html.replace('<head>', '<head><base href="/">', 1)
        html = (html.replace('__WEBUI_VERSION__', self.version)
                    .replace('__MAX_UPLOAD_BYTES__', str(self.settings.max_upload_bytes))
                    .replace('__CSRF_TOKEN_JSON__', json.dumps(session.csrf))
                    .replace('__CSP_IMG_EXTRA_JSON__', '[]'))
        html = html.replace('</head>', '<link rel="stylesheet" href="/multiuser/static/style.css">'
                            '<script defer src="/multiuser/static/client.js"></script></head>')
        return web.Response(text=html, content_type='text/html', headers={'Cache-Control': 'no-store'})

    async def static(self, request):
        root = ASSETS if request.path.startswith('/multiuser/static/') else SOURCE / 'static'
        relative = request.match_info['path']
        path = root / relative
        if path.is_symlink() or not path.resolve().is_relative_to(root) or not path.is_file():
            raise web.HTTPNotFound()
        return web.Response(body=path.read_bytes(), content_type=mimetypes.guess_type(path)[0] or 'application/octet-stream',
                            headers={'Cache-Control': 'no-cache'})

    async def service_worker(self, _request):
        # A trusted no-fetch worker clears legacy single-user caches and removes
        # itself. No per-tenant worker can install executable content at this URL.
        code = "self.addEventListener('install',e=>self.skipWaiting());self.addEventListener('activate',e=>e.waitUntil((async()=>{for(const k of await caches.keys())await caches.delete(k);await self.registration.unregister();await self.clients.claim();})()));"
        return web.Response(text=code, content_type='application/javascript', headers={'Cache-Control': 'no-store'})

    async def manifest(self, _request):
        return json_response({'name': 'Hermes', 'short_name': 'Hermes', 'start_url': '/',
                              'display': 'standalone', 'icons': [{'src': '/static/favicon-32.png', 'sizes': '32x32', 'type': 'image/png'}]})

    async def health(self, _request):
        return json_response({'status': 'ok', 'mode': 'multiuser'})

    async def updates(self, request):
        self.require(request)
        return json_response({'disabled': True, 'managed_by': 'trusted-operator-immutable-images'})

    async def proxy(self, request):
        principal = self.require(request)
        uid = principal.user_id
        path = request.path
        # Trusted gateway code and auth are never worker-controlled. Persistent
        # sharing, remote admin/control, provider account credentials and UI
        # extension installers are not delegated to private runtimes.
        denied = ('/extensions', '/api/extensions', '/api/auth', '/share', '/api/share',
                  '/api/update', '/api/restart', '/api/shutdown')
        if path.startswith(denied) or path.startswith('/multiuser') or (request.method in UNSAFE and path.startswith(('/api/provider', '/api/onboarding', '/api/config', '/api/env'))):
            raise web.HTTPForbidden(text='This operation is managed by the account gateway')
        runtime = self.store.runtime(uid)
        if not runtime or runtime['state'] != 'ready':
            return json_response({'error': 'Your private runtime is not ready', 'runtime_state': runtime['state'] if runtime else 'pending'}, status=503)
        if request.headers.get('Upgrade') or request.headers.get('Content-Encoding'):
            raise web.HTTPBadRequest(text='Unsupported proxy framing')
        if request.content_length is not None and request.content_length > self.settings.max_upload_bytes + 1024 * 1024:
            raise web.HTTPRequestEntityTooLarge(max_size=self.settings.max_upload_bytes, actual_size=request.content_length)
        # No gateway cookie, CSRF secret, identity or trusted-proxy header reaches
        # an Agent. A profile cookie can only address files inside its own mount.
        headers = {key: value for key, value in request.headers.items()
                   if key.lower() in ('content-type', 'accept', 'range', 'if-none-match', 'last-event-id')}
        headers.update({'Host': '127.0.0.1:8787', 'Origin': 'http://127.0.0.1:8787', 'Accept-Encoding': 'identity'})
        profile = request.cookies.get('hermes_profile')
        if profile and len(profile) < 256 and all(ch.isalnum() or ch in '._-~%' for ch in profile):
            headers['Cookie'] = 'hermes_profile=' + profile
        async def body():
            size = 0
            async for part in request.content.iter_chunked(65536):
                size += len(part)
                if size > self.settings.max_upload_bytes + 1024 * 1024:
                    raise web.HTTPRequestEntityTooLarge(max_size=self.settings.max_upload_bytes, actual_size=size)
                yield part
        payload = None
        if request.can_read_body:
            if request.content_length is None:
                payload = await request.read()
                headers['Content-Length'] = str(len(payload))
            else:
                payload = body()
                headers['Content-Length'] = str(request.content_length)
        session = self.sessions.get(uid)
        if session is None or session.closed:
            connector = aiohttp.UnixConnector(path=str(self.settings.relay_socket(uid)), limit=64)
            session = aiohttp.ClientSession(connector=connector, trust_env=False, auto_decompress=False,
                timeout=aiohttp.ClientTimeout(total=None, connect=5, sock_read=None))
            self.sessions[uid] = session
        response = None
        try:
            async with session.request(request.method, 'http://127.0.0.1:8787' + request.rel_url.path_qs,
                                       headers=headers, data=payload,
                                       allow_redirects=False) as upstream:
                if path == '/api/settings' and request.method == 'GET' and upstream.status == 200:
                    # Bundle identity and authentication belong to the trusted
                    # frontend/gateway. A private worker has different packaging
                    # metadata and intentionally has no browser-login cookie.
                    raw = bytearray()
                    async for chunk in upstream.content.iter_chunked(65536):
                        raw.extend(chunk)
                        if len(raw) > 2 * 1024 * 1024:
                            raise web.HTTPBadGateway()
                    if not self.store.session_by_hash(principal.token_hash):
                        raise web.HTTPForbidden()
                    value = json.loads(raw)
                    if not isinstance(value, dict):
                        raise web.HTTPBadGateway()
                    value.update(runtime_webui_version=value.get('webui_version'), webui_version=self.version,
                                 auth_enabled=True, password_auth_enabled=True,
                                 passkeys_enabled=False, passwordless_enabled=False)
                    return json_response(value)
                out_headers = {key: value for key, value in upstream.headers.items() if key.lower() not in HOP_HEADERS}
                out_headers['Cache-Control'] = 'no-store'
                mime = upstream.headers.get('Content-Type', '').split(';')[0].strip().lower()
                if mime in ('application/javascript', 'text/javascript', 'text/css'):
                    out_headers['Content-Type'] = 'application/octet-stream'
                    out_headers['Content-Disposition'] = 'attachment'
                if mime in ('text/html', 'image/svg+xml'):
                    out_headers['Content-Security-Policy'] = "sandbox; default-src 'none'; img-src data: blob:"
                response = web.StreamResponse(status=upstream.status, headers=out_headers)
                self.security_headers(response)
                for cookie in upstream.headers.getall('Set-Cookie', []):
                    parsed = http.cookies.SimpleCookie()
                    with contextlib.suppress(http.cookies.CookieError):
                        parsed.load(cookie)
                    if 'hermes_profile' in parsed:
                        value = parsed['hermes_profile'].value
                        if len(value) < 256 and all(ch.isalnum() or ch in '._-~%' for ch in value):
                            response.set_cookie('hermes_profile', value, path='/', secure=self.settings.secure,
                                                httponly=True, samesite='Strict')
                await response.prepare(request)
                pending = asyncio.create_task(upstream.content.readany())
                try:
                    while True:
                        done, _ = await asyncio.wait({pending}, timeout=0.5)
                        if self.store.session_by_hash(principal.token_hash) is None:
                            break
                        if not done:
                            continue
                        chunk = pending.result()
                        if not chunk:
                            break
                        await response.write(chunk)
                        pending = asyncio.create_task(upstream.content.readany())
                finally:
                    pending.cancel()
                await response.write_eof()
                return response
        except (aiohttp.ClientError, OSError, TimeoutError):
            if response is not None and response.prepared:
                with contextlib.suppress(ConnectionError):
                    await response.write_eof()
                return response
            return json_response({'error': 'Your private runtime is unavailable'}, status=503)


def create_app(settings):
    gateway = Gateway(settings)
    app = web.Application(client_max_size=settings.max_upload_bytes + 1024 * 1024,
                          middlewares=[gateway.boundary])
    app[web.AppKey('gateway', Gateway)] = gateway
    app.on_startup.append(gateway.start)
    app.on_cleanup.append(gateway.close)
    app.router.add_get('/health', gateway.health)
    app.router.add_get('/api/updates/check', gateway.updates)
    app.router.add_post('/api/updates/check', gateway.updates)
    app.router.add_get('/login', gateway.login_page)
    app.router.add_post('/api/auth/login', gateway.login)
    app.router.add_post('/api/auth/logout', gateway.logout)
    app.router.add_get('/api/auth/status', gateway.auth_status)
    app.router.add_get('/multiuser/api/me', gateway.me)
    app.router.add_get('/multiuser/api/users', gateway.users)
    app.router.add_post('/multiuser/api/users', gateway.users)
    app.router.add_post('/multiuser/api/users/{uid}', gateway.update_user)
    for path, handler in [('/multiuser/api/providers', gateway.providers),
                          ('/multiuser/api/templates', gateway.templates),
                          ('/multiuser/api/tools', gateway.tools)]:
        app.router.add_get(path, handler)
        app.router.add_post(path, handler)
    app.router.add_get('/multiuser/static/{path:.*}', gateway.static)
    app.router.add_get('/static/{path:.*}', gateway.static)
    app.router.add_get('/sw.js', gateway.service_worker)
    app.router.add_get('/manifest.json', gateway.manifest)
    for path in ('/', '/index.html', '/sessions', '/session/{sid}', '/multiuser/admin'):
        app.router.add_get(path, gateway.index)
    app.router.add_route('*', '/{path:.*}', gateway.proxy)
    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('/srv/hermes'))
    args = parser.parse_args()
    settings = Settings.load(args.root)
    if os.geteuid() != settings.gateway_uid:
        raise SystemExit('Run the gateway as its dedicated non-root gateway UID')
    web.run_app(create_app(settings), host=settings.bind_host, port=settings.port, access_log=None)


if __name__ == '__main__':
    main()
