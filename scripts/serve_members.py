#!/usr/bin/env python3
"""Serve private username/password chat on loopback, without Agent execution."""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8789)
    args = parser.parse_args()
    from api.access_admin import configured_store
    from api.member_routes import member_enabled
    from api.user_roles import has_accounts, load_users
    if not member_enabled() or not has_accounts():
        parser.error('Configure username/password accounts and HERMES_WEBUI_MEMBER_CHAT=1 first')
    store = configured_store()
    admins = [account for account in load_users().values() if account['role']=='admin' and account.get('id')]
    if store is None or not admins:
        parser.error('An initialized access policy and administrator with an immutable ID are required')
    try:
        for admin in admins:
            try:
                store.snapshot(admin['id'])
                break
            except PermissionError:
                continue
        else:
            parser.error('No active administrator is registered in access policy')
    except RuntimeError:
        parser.error('Access policy is unavailable')
    from api.member_server import MemberHandler
    from server import QuietHTTPServer
    httpd = QuietHTTPServer(('127.0.0.1', args.port), MemberHandler)
    print(f'Private chat listening on http://127.0.0.1:{httpd.server_port}', flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == '__main__':
    main()
