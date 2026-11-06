"""Dedicated username/password chat server with no legacy execution routes.

Uses the shared authentication, CSRF, bounded request framing and static helpers.
Importing the shared Handler does not start its __main__ lifecycle or watchers.
"""
from urllib.parse import urlsplit

from server import Handler

_GET = {'/login', '/health', '/favicon.ico', '/sw.js', '/member', '/admin/users',
        '/api/auth/status', '/api/admin/access', '/api/admin/users'}
_ASSETS = {'login.js', 'access-admin.js', 'access-admin.css', 'member.js', 'member.css', 'favicon.svg', 'favicon-32.png'}
_POST = {'/api/auth/login', '/api/auth/logout', '/api/admin/access', '/api/admin/users'}


class MemberHandler(Handler):
    def _refuse(self):
        payload = b'{"error":"Not available in private chat mode"}'
        self.send_response(404)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == '/':
            from api.auth import get_session_info, parse_cookie
            from api.user_roles import load_users, resolve_session_account
            info = get_session_info(parse_cookie(self))
            target = 'login'
            if info and info.get('auth_type') == 'local' and resolve_session_account(info)[0]:
                actor = load_users().get(info.get('username'))
                target = 'admin/users' if actor and actor['role'] == 'admin' else 'member'
            self.send_response(302)
            self.send_header('Location', target)
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        if path in _GET or path.startswith('/api/member/') or (path.startswith('/static/') and path[8:] in _ASSETS):
            return super().do_GET()
        return self._refuse()

    def do_POST(self):
        path = urlsplit(self.path).path
        if path in _POST or path.startswith('/api/member/'):
            return super().do_POST()
        return self._refuse()

    do_PUT = _refuse
    do_DELETE = _refuse
    do_PATCH = _refuse
