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
    if parsed.path not in {"/api/admin/access", "/api/access/me"}:
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
        if handler.command == "GET":
            return j(handler, store.snapshot(actor["id"]))
        if handler.command != "POST":
            return bad(handler, "Method not allowed", 405)
        if not isinstance(body, dict):
            return bad(handler, "JSON object required", 400)
        action = body.get("action")
        if action == "account":
            # Account identity is resolved from the trusted local store. A body
            # cannot invent a login identity or a role different from that store.
            account = load_users().get(body.get("username"))
            if not account or not account.get("id"):
                return bad(handler, "Create the login account with webui_users.py first", 400)
            store.put_account(actor["id"], account["id"], role=account["role"], enabled=body.get("enabled", True))
        elif action == "resource":
            store.put_resource(actor["id"], body.get("id"), kind=body.get("kind"),
                               label=body.get("label"), binding=body.get("binding"))
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
