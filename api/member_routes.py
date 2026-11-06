"""Authenticated tool-free member API. Every identity comes from a live login."""
import base64
import os
from pathlib import Path
from urllib.parse import parse_qs

from api.access_policy import AccessDenied, PolicyUnavailable
from api.member_chat import ConversationBusy, MemberChat, ReferenceFolders, parse_context
from api.provider_broker import ProviderFailure

_REFERENCE_PATHS = {"/api/member/references", "/api/member/reference/files", "/api/member/reference/file"}
_ADMIN_PREFIX = "/api/member/admin/"
_ADMIN_PATHS = {"/api/member/admin/conversations", "/api/member/admin/conversation"}


def member_enabled():
    return os.getenv("HERMES_WEBUI_MEMBER_CHAT", "").strip() == "1"


def member_root(store):
    path = os.getenv("HERMES_WEBUI_MEMBER_DATA_DIR", "").strip()
    return Path(path) if path else store.path.parent / "member-data"


def local_actor(handler):
    from api.auth import ensure_trusted_auth_session
    from api.user_roles import load_users, resolve_session_account
    info = ensure_trusted_auth_session(handler)
    if not info or info.get("auth_type") != "local" or not resolve_session_account(info)[0]:
        raise AccessDenied("Username/password login required")
    actor = load_users().get(info.get("username"))
    if not actor or not actor.get("id"):
        raise AccessDenied("Account identity unavailable")
    return actor, info


def _handle_reference(handler, parsed, store, account_id):
    """Read-only folder references; identity comes only from the live login.

    ``owner`` is untrusted input and is re-authorized against the live policy
    on every request. Every non-GET method is refused before any file access.
    """
    from api.helpers import j
    if handler.command != "GET":
        return j(handler, {"error": "Reference folders are read only"}, status=405, extra_headers={"Allow": "GET"})
    folders = ReferenceFolders(store)
    if parsed.path == "/api/member/references":
        return j(handler, {"references": folders.targets(account_id)})
    query = parse_qs(parsed.query)
    owner, path = query.get("owner", [""])[0], query.get("path", [""])[0]
    if parsed.path == "/api/member/reference/files":
        files, truncated = folders.list_files(account_id, owner, path)
        return j(handler, {"owner": owner, "path": path, "read_only": True, "files": files, "truncated": truncated})
    content = folders.read_file(account_id, owner, path)
    return j(handler, {"owner": owner, "path": path, "read_only": True, "size": len(content),
                       "content": base64.b64encode(content).decode()})


def _handle_admin_conversations(handler, parsed, store, actor):
    """Read-only administrator view of every account's member conversations.

    Administrator authority is re-read on every request: from the live login
    store (``actor`` was just resolved by ``local_actor``) and from the live
    policy inside the reading transaction. Non-administrators, every non-GET
    method and unknown admin paths get the same generic 403 before any
    conversation is looked up. There is no administrator send/rename/delete
    path; content reads of other accounts' conversations are audited.
    """
    from api.helpers import j
    if handler.command != "GET" or actor.get("role") != "admin" or parsed.path not in _ADMIN_PATHS:
        raise AccessDenied("Administrator read-only view")
    service = MemberChat(store, member_root(store))
    if parsed.path == "/api/member/admin/conversations":
        return j(handler, {"conversations": service.admin_conversations(actor["id"]), "read_only": True})
    conversation_id = parse_qs(parsed.query).get("id", [""])[0]
    return j(handler, service.admin_read(actor["id"], conversation_id))


def handle_member(handler, parsed, body=None):
    from api.access_admin import configured_store
    from api.helpers import bad, j
    from api.user_roles import resolve_session_account
    if not parsed.path.startswith("/api/member/"):
        return False
    if not member_enabled():
        return bad(handler, "Member chat is not enabled", 503)
    try:
        actor, info = local_actor(handler)
        store = configured_store()
        if store is None:
            raise PolicyUnavailable("Policy is not configured")
        store.account_snapshot(actor["id"])
        if parsed.path == "/api/member/catalog" and handler.command == "GET":
            return j(handler, {**store.account_snapshot(actor["id"]), "chat_available": True,
                               "username": actor["username"], "role": actor["role"], "tools_available": False})
        if parsed.path.startswith(_ADMIN_PREFIX):
            return _handle_admin_conversations(handler, parsed, store, actor)
        if parsed.path in _REFERENCE_PATHS:
            return _handle_reference(handler, parsed, store, actor["id"])
        service = MemberChat(store, member_root(store))
        if parsed.path == "/api/member/conversations":
            if handler.command == "GET":
                return j(handler, {"conversations": service.conversations(actor["id"])})
            if handler.command == "POST":
                return j(handler, service.create(parse_context(actor["id"], body)))
        if parsed.path == "/api/member/conversation" and handler.command == "GET":
            conversation_id = parse_qs(parsed.query).get("id", [""])[0]
            return j(handler, service.read(actor["id"], conversation_id))
        if handler.command != "POST" or not isinstance(body, dict):
            return bad(handler, "Unknown member operation", 404)
        if parsed.path == "/api/member/chat":
            response = service.chat(actor["id"], body.get("conversation_id"), body.get("message"))
            if not resolve_session_account(info)[0]:
                raise AccessDenied("Login authority changed during the request")
            return j(handler, response)
        if parsed.path == "/api/member/files":
            context = parse_context(actor["id"], body.get("context"))
            path = body.get("path", "")
            action = body.get("action")
            if action == "list":
                return j(handler, {"files": service.list_files(context, path)})
            if action == "read":
                return j(handler, {"content": base64.b64encode(service.read_file(context, path)).decode()})
            if action in {"write", "mkdir"}:
                value = base64.b64decode(body.get("content", ""), validate=True)
                service.write_file(context, path, value, directory=action == "mkdir")
                return j(handler, {"ok": True})
        return bad(handler, "Unknown member operation", 404)
    except AccessDenied:
        return bad(handler, "Access is not granted to this account", 403)
    except ConversationBusy:
        return bad(handler, "A response is already in progress", 409)
    except ProviderFailure:
        return bad(handler, "Provider request failed; contact your administrator", 502)
    except PolicyUnavailable:
        return bad(handler, "Access policy is unavailable", 503)
    except (ValueError, TypeError, OSError):
        return bad(handler, "Invalid or unavailable private resource", 400)


def serve_access_page(handler, *, admin=False):
    from api.access_admin import configured_store
    from api.auth import csrf_token_for_session, parse_cookie
    from api.helpers import bad, t
    try:
        actor, _ = local_actor(handler)
        if admin and actor["role"] != "admin":
            raise AccessDenied("Administrator required")
        store = configured_store()
        if store is None:
            raise PolicyUnavailable("Policy not configured")
        if admin:
            store.snapshot(actor["id"])
        else:
            store.account_snapshot(actor["id"])
        token = csrf_token_for_session(parse_cookie(handler)) or ""
        page = "access-admin.html" if admin else "member.html"
        html = (Path(__file__).parent.parent / "static" / page).read_text()
        return t(handler, html.replace("__ACCESS_CSRF__", token), content_type="text/html; charset=utf-8",
                 extra_headers={"Cache-Control": "no-store"})
    except AccessDenied:
        return bad(handler, "Account access denied", 403)
    except PolicyUnavailable:
        return bad(handler, "Configure the account access policy first", 503)
