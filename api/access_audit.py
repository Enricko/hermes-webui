"""Audit of administrator reads of other accounts' private member conversations.

Rows record who read whose conversation and when: account IDs, the
conversation ID, an action and a timestamp. They never contain message
content, titles or provider data. Callers write the row inside the same policy
transaction that authorizes the read, so a failed audit write aborts the read
(fail closed). An administrator reading their own conversation is not audited.
"""
from __future__ import annotations

import time

from api.access_policy import AccessDenied

AUDIT_ACTIONS = frozenset({"read"})

_AUDIT_TABLE = ("CREATE TABLE IF NOT EXISTS member_admin_audit ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, admin_account_id TEXT NOT NULL, "
                "owner_account_id TEXT NOT NULL, conversation_id TEXT NOT NULL, "
                "action TEXT NOT NULL CHECK(action IN ('read')), created REAL NOT NULL, "
                "CHECK(admin_account_id <> owner_account_id))")
_AUDIT_INDEX = ("CREATE INDEX IF NOT EXISTS member_admin_audit_conversation "
                "ON member_admin_audit(conversation_id, owner_account_id)")


def ensure_audit_table(db):
    """Create the audit relation in the policy database (idempotent)."""
    db.execute(_AUDIT_TABLE)
    db.execute(_AUDIT_INDEX)


def record_admin_view(db, *, admin_id: str, owner_id: str, conversation_id: str, action: str = "read"):
    """Append one audit row within the caller's write transaction.

    Raises instead of returning when the row cannot be written; the caller's
    transaction then rolls back and the read is denied.
    """
    if action not in AUDIT_ACTIONS or admin_id == owner_id:
        raise AccessDenied("Administrator read cannot be audited")
    cursor = db.execute(
        "INSERT INTO member_admin_audit(admin_account_id,owner_account_id,conversation_id,action,created) "
        "VALUES (?,?,?,?,?)", (admin_id, owner_id, conversation_id, action, time.time()))
    if cursor.rowcount != 1:
        raise AccessDenied("Administrator read cannot be audited")


def admin_view_summary(db, *, owner_id: str, conversation_id: str) -> dict:
    """Owner transparency: count and time only, never administrator identity."""
    count, last = db.execute(
        "SELECT COUNT(*), MAX(created) FROM member_admin_audit WHERE conversation_id=? AND owner_account_id=?",
        (conversation_id, owner_id)).fetchone()
    return {"admin_views": count, "last_admin_view": last}
