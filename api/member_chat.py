"""Private multi-user chat and files, with no executable agent/tool surface.

This deliberately never imports AIAgent or forwards requests to legacy routes.
Messages/skills are data sent to a granted managed provider. Full Agent tools
remain behind the isolated-runtime release gate.
"""
from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import secrets
import stat
import time

from api.access_audit import admin_view_summary, ensure_audit_table, record_admin_view
from api.access_policy import AccessContext, AccessDenied, _login_usernames
from api.provider_broker import CredentialVault, infer

_FILE_LIMIT = 2 * 1024 * 1024
_REFERENCE_LIST_LIMIT = 2000
# Hidden from read-only references: dot entries (.env, .ssh, .git, .tmp, …) and
# common key/credential files. Hidden names are never listed nor readable.
_REFERENCE_SECRET_NAMES = frozenset({"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "auth.json", "credentials.json"})
_REFERENCE_SECRET_SUFFIXES = (".key", ".pem", ".p12", ".pfx", ".kdbx")


class ConversationBusy(RuntimeError):
    pass


def _relative_pieces(relative):
    """Validate a client-supplied relative path; no host path is ever accepted."""
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("Private file operations require the verified POSIX backend")
    if not isinstance(relative, str) or len(relative) > 2048 or relative.startswith("/") or "\\" in relative or "\0" in relative:
        raise ValueError("Invalid private path")
    pieces = relative.split("/") if relative else []
    if any(part in {"", ".", ".."} for part in pieces):
        raise ValueError("Invalid private path")
    return pieces


def _open_directory(root, pieces, *, parent=False):
    """Walk ``pieces`` below ``root`` by descriptor; no component may be a symlink."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(root, flags)
    try:
        for piece in pieces[:-1] if parent else pieces:
            child = os.open(piece, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor, pieces[-1] if parent and pieces else None
    except BaseException:
        os.close(descriptor)
        raise


def _scan_directory(descriptor, skip, *, regular_only=False):
    with os.scandir(descriptor) as entries:
        rows = [{"name": entry.name, "directory": entry.is_dir(follow_symlinks=False),
                 "size": entry.stat(follow_symlinks=False).st_size} for entry in entries
                if not entry.is_symlink() and not skip(entry.name)
                and (not regular_only or entry.is_dir(follow_symlinks=False) or entry.is_file(follow_symlinks=False))]
    return sorted(rows, key=lambda row: (not row["directory"], row["name"]))


def _read_regular(descriptor, leaf):
    if not leaf:
        raise ValueError("File path required")
    fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
    with os.fdopen(fd, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("Only regular files are supported")
        value = source.read(_FILE_LIMIT + 1)
    if len(value) > _FILE_LIMIT:
        raise ValueError("File exceeds the 2 MiB limit")
    return value


def _reference_hidden(name):
    lowered = name.lower()
    return lowered.startswith(".") or lowered in _REFERENCE_SECRET_NAMES or lowered.endswith(_REFERENCE_SECRET_SUFFIXES)


def parse_context(account_id, body):
    if not isinstance(body, dict):
        raise ValueError("Selection is required")
    skills = body.get("skills", [])
    if not isinstance(skills, list) or len(skills) > 128 or any(not isinstance(skill, str) for skill in skills):
        raise ValueError("Invalid skill selection")
    if not isinstance(body.get("model"), str) or len(body["model"]) > 256:
        raise ValueError("Model selection is required")
    return AccessContext(account_id, body.get("profile_id"), body.get("workspace_id"),
                         body.get("connection_id"), body["model"], tuple(sorted(set(skills))))


class MemberChat:
    def __init__(self, policy, root: Path):
        self.policy = policy
        self.root = Path(root)
        self.vault = CredentialVault(self.root / "credentials.json")
        with policy._transaction(write=True) as db:
            db.execute("CREATE TABLE IF NOT EXISTS member_conversations (id TEXT PRIMARY KEY, owner TEXT NOT NULL, "
                       "context TEXT NOT NULL, title TEXT NOT NULL, created REAL NOT NULL, busy TEXT, lease REAL)")
            db.execute("CREATE TABLE IF NOT EXISTS member_messages (conversation TEXT NOT NULL, ordinal INTEGER NOT NULL, "
                       "role TEXT NOT NULL, content TEXT NOT NULL, PRIMARY KEY(conversation,ordinal), "
                       "FOREIGN KEY(conversation) REFERENCES member_conversations(id))")
            ensure_audit_table(db)

    @staticmethod
    def _owner_consistent(row):
        """A row whose stored context names a different account is never served."""
        try:
            return json.loads(row["context"]).get("account_id") == row["owner"]
        except (ValueError, TypeError, AttributeError):
            return False

    @staticmethod
    def _active_owners(db):
        """Accounts enabled in BOTH authorities: the policy DB and the login store.

        Administrators may not read (or list) conversations of a disabled
        account; the conversations are retained but sealed until re-enabled.
        """
        enabled = {row["id"] for row in db.execute("SELECT id FROM accounts WHERE enabled=1")}
        return enabled & set(_login_usernames())

    @staticmethod
    def _context(raw):
        fields = json.loads(raw)
        fields["skills"] = tuple(fields["skills"])
        fields["tools"] = tuple(fields.get("tools", ()))
        return AccessContext(**fields)

    def _conversation(self, db, account_id, conversation_id):
        if not isinstance(conversation_id, str) or len(conversation_id) != 32:
            raise AccessDenied("Conversation is unavailable")
        row = db.execute("SELECT * FROM member_conversations WHERE id=? AND owner=?", (conversation_id, account_id)).fetchone()
        if row is None:
            raise AccessDenied("Conversation is unavailable")
        context = self._context(row["context"])
        if context.account_id != account_id:
            raise AccessDenied("Conversation ownership is invalid")
        self.policy._authorize(db, context)
        return row, context

    def conversations(self, account_id):
        with self.policy._transaction() as db:
            self.policy._account(db, account_id)
            result = []
            for row in db.execute("SELECT * FROM member_conversations WHERE owner=? ORDER BY created DESC", (account_id,)):
                try:
                    self.policy._authorize(db, self._context(row["context"]))
                except AccessDenied:
                    continue
                result.append({"id": row["id"], "title": row["title"], "context": json.loads(row["context"])})
            return result

    def create(self, context):
        with self.policy._transaction(write=True) as db:
            self.policy._authorize(db, context)
            conversation_id = secrets.token_hex(16)
            db.execute("INSERT INTO member_conversations VALUES (?,?,?,?,?,NULL,NULL)",
                       (conversation_id, context.account_id, json.dumps(asdict(context)), "New conversation", time.time()))
            return {"id": conversation_id, "context": asdict(context), "messages": []}

    def read(self, account_id, conversation_id):
        """Owner read. ``admin_views``/``last_admin_view`` disclose how often and
        when administrators read this conversation, never which administrator."""
        with self.policy._transaction() as db:
            row, context = self._conversation(db, account_id, conversation_id)
            messages = [dict(message) for message in db.execute(
                "SELECT role,content FROM member_messages WHERE conversation=? ORDER BY ordinal", (conversation_id,))]
            views = admin_view_summary(db, owner_id=account_id, conversation_id=row["id"])
            return {"id": row["id"], "title": row["title"], "context": asdict(context), "messages": messages, **views}

    def admin_conversations(self, admin_id):
        """Metadata of every member conversation, for a live enabled administrator.

        Contains no message content. Titles are derived from the first message,
        so a title is included only for the administrator's own conversations.
        Listing is not a content read and is not audited.
        """
        with self.policy._transaction() as db:
            self.policy._account(db, admin_id, admin=True)
            rows = db.execute("SELECT id,owner,context,title,created FROM member_conversations "
                              "ORDER BY created DESC, id").fetchall()
            active = self._active_owners(db)
        names = _login_usernames()
        result = []
        for row in rows:
            if not self._owner_consistent(row):
                continue
            own = row["owner"] == admin_id
            if not own and row["owner"] not in active:
                continue
            result.append({"id": row["id"], "owner_id": row["owner"], "owner_username": names.get(row["owner"]),
                           "created": row["created"], "own": own, **({"title": row["title"]} if own else {})})
        return result

    def admin_read(self, admin_id, conversation_id):
        """Read-only administrator view of another account's conversation.

        The live administrator check, the conversation lookup and the audit row
        share one write transaction. If the audit insert or the commit fails,
        the exception propagates and no content is returned (fail closed).
        Unknown, malformed and inconsistent IDs raise the same AccessDenied.
        The administrator's own conversation takes the ordinary owner path and
        is not audited. There is deliberately no administrator write path.
        """
        if not isinstance(conversation_id, str) or len(conversation_id) != 32:
            raise AccessDenied("Conversation is unavailable")
        with self.policy._transaction(write=True) as db:
            self.policy._account(db, admin_id, admin=True)
            row = db.execute("SELECT * FROM member_conversations WHERE id=?", (conversation_id,)).fetchone()
            if row is None or not self._owner_consistent(row):
                raise AccessDenied("Conversation is unavailable")
            own = row["owner"] == admin_id
            if not own and row["owner"] not in self._active_owners(db):
                raise AccessDenied("Conversation is unavailable")
            if not own:
                messages = [dict(message) for message in db.execute(
                    "SELECT role,content FROM member_messages WHERE conversation=? ORDER BY ordinal", (row["id"],))]
                record_admin_view(db, admin_id=admin_id, owner_id=row["owner"], conversation_id=row["id"])
        if own:
            return {**self.read(admin_id, conversation_id), "own": True, "read_only": False}
        return {"id": row["id"], "owner_id": row["owner"], "owner_username": _login_usernames().get(row["owner"]),
                "title": row["title"], "created": row["created"], "messages": messages,
                "own": False, "read_only": True}

    def chat(self, account_id, conversation_id, message):
        if not isinstance(message, str) or not message.strip() or len(message) > 64_000:
            raise ValueError("Message must contain 1–64000 characters")
        token = secrets.token_hex(16)
        with self.policy._transaction(write=True) as db:
            row, context = self._conversation(db, account_id, conversation_id)
            if row["busy"] and row["lease"] > time.time():
                raise ConversationBusy("A response is already in progress")
            db.execute("UPDATE member_conversations SET busy=?,lease=? WHERE id=?", (token, time.time() + 120, conversation_id))
            messages = [dict(item) for item in db.execute("SELECT role,content FROM member_messages WHERE conversation=? ORDER BY ordinal", (conversation_id,))]
        try:
            if sum(len(item["content"]) for item in messages) + len(message) > 256_000:
                raise ValueError("Conversation is too long; start a new conversation")
            reply, admission = infer(self.policy, self.vault, context, [*messages, {"role": "user", "content": message}])
            with self.policy._transaction(write=True) as db:
                row, context = self._conversation(db, account_id, conversation_id)
                current = self.policy._authorize(db, context)
                if row["busy"] != token or current.revision != admission.revision:
                    raise AccessDenied("Conversation authority changed while generating the response")
                ordinal = db.execute("SELECT COUNT(*) FROM member_messages WHERE conversation=?", (conversation_id,)).fetchone()[0]
                db.executemany("INSERT INTO member_messages VALUES (?,?,?,?)", [
                    (conversation_id, ordinal, "user", message), (conversation_id, ordinal + 1, "assistant", reply)])
                db.execute("UPDATE member_conversations SET title=?,busy=NULL,lease=NULL WHERE id=?",
                           (message[:80] if ordinal == 0 else row["title"], conversation_id))
            return {"reply": reply}
        finally:
            with self.policy._transaction(write=True) as db:
                db.execute("UPDATE member_conversations SET busy=NULL,lease=NULL WHERE id=? AND busy=?", (conversation_id, token))

    def _workspace_fd(self, context, relative, *, parent=False):
        self.policy.authorize(context)
        pieces = _relative_pieces(relative)
        # IDs were validated by live policy above. No host path is accepted.
        root = self.root / "files" / context.account_id / context.workspace_id
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
        return _open_directory(root, pieces, parent=parent)

    def list_files(self, context, path=""):
        descriptor, _ = self._workspace_fd(context, path)
        try:
            rows = _scan_directory(descriptor, lambda name: name.startswith(".upload-"))
            self.policy.authorize(context)
            return rows
        finally:
            os.close(descriptor)

    def read_file(self, context, path):
        descriptor, leaf = self._workspace_fd(context, path, parent=True)
        try:
            value = _read_regular(descriptor, leaf)
            self.policy.authorize(context)
            return value
        finally:
            os.close(descriptor)

    def write_file(self, context, path, value, *, directory=False):
        if not isinstance(value, bytes) or len(value) > _FILE_LIMIT:
            raise ValueError("File exceeds the 2 MiB limit")
        descriptor, leaf = self._workspace_fd(context, path, parent=True)
        temporary = ".upload-" + secrets.token_hex(16)
        try:
            if not leaf:
                raise ValueError("File path required")
            self.policy.authorize(context)
            if directory:
                os.mkdir(leaf, mode=0o700, dir_fd=descriptor)
            else:
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
                with os.fdopen(fd, "wb") as output:
                    output.write(value)
                    output.flush()
                    os.fsync(output.fileno())
                self.policy.authorize(context)
                os.replace(temporary, leaf, src_dir_fd=descriptor, dst_dir_fd=descriptor)
        finally:
            try:
                os.unlink(temporary, dir_fd=descriptor)
            except FileNotFoundError:
                pass
            os.close(descriptor)


class ReferenceFolders:
    """Administrator-granted, read-only view of another login's private folder.

    Only the target's single login-scoped root (``/<login>``, bound to its
    immutable account ID) is exposed. Its conversations, member-data files,
    grants and credentials are never read. The live reference grant is checked
    before and after each filesystem access. Symlinks (any component), hidden
    entries and common secret files are refused. Deliberately there is no
    write, mkdir, rename, upload or delete operation.
    """

    def __init__(self, policy):
        self.policy = policy

    def targets(self, account_id):
        return self.policy.account_snapshot(account_id)["references"]

    @staticmethod
    def _root(target_id) -> Path:
        from api import user_roles
        from api.account_admin import account_transaction
        from api.workspace_sandbox import PrivateWorkspace
        try:
            with account_transaction(write=False) as data:
                for name, record in data["users"].items():
                    if isinstance(record, dict) and record.get("id") == target_id:
                        if user_roles._normalize_record(name, record) is None:
                            break
                        return PrivateWorkspace.from_account({**record, "username": name}).host_path
        except (OSError, RuntimeError, ValueError, TypeError):
            pass
        raise AccessDenied("Reference folder is unavailable")

    def _open(self, account_id, target_id, relative, *, parent=False):
        self.policy.authorize_reference(account_id, target_id)
        root = self._root(target_id)
        pieces = _relative_pieces(relative)
        if any(_reference_hidden(piece) for piece in pieces):
            raise FileNotFoundError("Reference entry is unavailable")
        return _open_directory(root, pieces, parent=parent)

    def list_files(self, account_id, target_id, path=""):
        descriptor, _ = self._open(account_id, target_id, path)
        try:
            rows = _scan_directory(descriptor, _reference_hidden, regular_only=True)
        finally:
            os.close(descriptor)
        self.policy.authorize_reference(account_id, target_id)
        return rows[:_REFERENCE_LIST_LIMIT], len(rows) > _REFERENCE_LIST_LIMIT

    def read_file(self, account_id, target_id, path):
        descriptor, leaf = self._open(account_id, target_id, path, parent=True)
        try:
            value = _read_regular(descriptor, leaf)
        finally:
            os.close(descriptor)
        self.policy.authorize_reference(account_id, target_id)
        return value
