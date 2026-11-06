"""Administrator-only policy API, separate from worker execution.

Routes are opt-in through HERMES_WEBUI_ACCESS_POLICY_FILE. An uninitialized or
unreadable configured authority returns 503, never a new empty database.
"""
from __future__ import annotations

import os

from api.access_policy import AccessDenied, PolicyStore, PolicyUnavailable


def configured_store() -> PolicyStore | None:
    path = os.getenv("HERMES_WEBUI_ACCESS_POLICY_FILE", "").strip()
    return PolicyStore(path) if path else None


def handle_access_admin(handler, parsed, body=None):
    """Caller uses normal auth and, on POST, the shared CSRF/body gates."""
    if parsed.path not in {"/api/admin/access", "/api/admin/users", "/api/access/me"}:
        return False
    from api.auth import ensure_trusted_auth_session
    from api.helpers import bad, j
    from api.user_roles import load_users, resolve_session_account

    info = ensure_trusted_auth_session(handler)
    if not info or info.get("auth_type") != "local" or not resolve_session_account(info)[0]:
        return bad(handler, "Administrator account required", 403)
    actor = load_users().get(info.get("username"))
    member_catalog = parsed.path == "/api/access/me" and handler.command == "GET"
    if not actor or not actor.get("id") or (not member_catalog and actor["role"] != "admin"):
        return bad(handler, "Administrator account with immutable ID required", 403)
    store = configured_store()
    if store is None:
        return bad(handler, "Access policy is not configured", 503)
    try:
        if member_catalog:
            return j(handler, store.account_snapshot(actor["id"]))
        if parsed.path == "/api/admin/users":
            from api.account_admin import edit_account, public_accounts

            # Policy administration and login administration both require an
            # active administrator in their respective authoritative stores.
            snapshot = store.snapshot(actor["id"])
            if handler.command == "GET":
                return j(handler, {"users": public_accounts(actor["id"]), "policy": snapshot})
            if handler.command != "POST":
                return bad(handler, "Method not allowed", 405)
            if not isinstance(body, dict) or body.get("action") not in {"create", "update"}:
                return bad(handler, "Account action must be create or update", 400)
            result = edit_account(actor["id"], username=body.get("username"), role=body.get("role", "user"),
                                  enabled=body.get("enabled", True), password=body.get("password") or None,
                                  create=body["action"] == "create", policy=store)
            return j(handler, {"ok": True, "user": result})
        if handler.command == "GET":
            return j(handler, store.snapshot(actor["id"]))
        if handler.command != "POST":
            return bad(handler, "Method not allowed", 405)
        if not isinstance(body, dict):
            return bad(handler, "JSON object required", 400)
        action = body.get("action")
        if action == 'import_profiles':
            from api.profiles import list_profiles_api
            names = [row['name'] for row in list_profiles_api() if isinstance(row,dict) and row.get('name')]
            return j(handler, {'ok':True,'profiles':store.import_profiles(actor['id'],names)})
        if action == "account":
            # Account identity is resolved from the trusted local store. A body
            # cannot invent a login identity or a role different from that store.
            account = load_users().get(body.get("username"))
            if not account or not account.get("id"):
                return bad(handler, "Create the login account with webui_users.py first", 400)
            store.put_account(actor["id"], account["id"], role=account["role"], enabled=body.get("enabled", True))
        elif action == "resource":
            credential = body.get("credential")
            if body.get('kind') == 'tool':
                from api.workspace_sandbox import validate_tool
                if not isinstance(body.get('binding'),dict):
                    raise ValueError('Tool binding is required')
                validate_tool(body['binding'].get('executable'))
            if credential:
                from api.provider_broker import CredentialVault
                if body.get("kind") != "connection":
                    raise ValueError("Only connections have credentials")
                CredentialVault.validate_credential(credential)
            if body.get("kind") == "connection" and (credential or os.getenv("HERMES_WEBUI_MEMBER_CHAT") == "1"):
                from api.provider_broker import validate_connection
                validate_connection(body.get("binding") or {})
            store.put_resource(actor["id"], body.get("id"), kind=body.get("kind"),
                               label=body.get("label"), binding=body.get("binding"))
            if credential:
                from api.member_routes import member_root
                CredentialVault(member_root(store) / "credentials.json").put(body["id"], credential, body["binding"])
        elif action == "grants":
            store.replace_grants(actor["id"], body.get("account_id"), body.get("grants"))
        else:
            return bad(handler, "Unknown access policy action", 400)
        return j(handler, {"ok": True, "revision": store.snapshot(actor["id"])["revision"]})
    except AccessDenied:
        return bad(handler, "Access policy rejected this operation", 403)
    except PolicyUnavailable:
        return bad(handler, "Access policy unavailable", 503)
    except (ValueError, TypeError):
        return bad(handler, "Invalid access policy request", 400)
