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
import time

from api.access_policy import AccessContext, AccessDenied
from api.provider_broker import CredentialVault, infer


class ConversationBusy(RuntimeError):
    pass


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

    @staticmethod
    def _context(raw):
        fields = json.loads(raw)
        fields["skills"] = tuple(fields["skills"])
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
        with self.policy._transaction() as db:
            row, context = self._conversation(db, account_id, conversation_id)
            messages = [dict(message) for message in db.execute(
                "SELECT role,content FROM member_messages WHERE conversation=? ORDER BY ordinal", (conversation_id,))]
            return {"id": row["id"], "title": row["title"], "context": asdict(context), "messages": messages}

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
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise ValueError("Private file operations require the verified POSIX backend")
        if not isinstance(relative, str) or len(relative) > 2048 or relative.startswith("/") or "\\" in relative or "\0" in relative:
            raise ValueError("Invalid private path")
        pieces = relative.split("/") if relative else []
        if any(part in {"", ".", ".."} for part in pieces):
            raise ValueError("Invalid private path")
        # IDs were validated by live policy above. No host path is accepted.
        root = self.root / "files" / context.account_id / context.workspace_id
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
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

    def list_files(self, context, path=""):
        descriptor, _ = self._workspace_fd(context, path)
        try:
            with os.scandir(descriptor) as entries:
                rows = [{"name": entry.name, "directory": entry.is_dir(follow_symlinks=False),
                         "size": entry.stat(follow_symlinks=False).st_size} for entry in entries
                        if not entry.is_symlink() and not entry.name.startswith(".upload-")]
            self.policy.authorize(context)
            return sorted(rows, key=lambda row: (not row["directory"], row["name"]))
        finally:
            os.close(descriptor)

    def read_file(self, context, path):
        descriptor, leaf = self._workspace_fd(context, path, parent=True)
        try:
            if not leaf:
                raise ValueError("File path required")
            fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
            with os.fdopen(fd, "rb") as source:
                import stat
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    raise ValueError("Only regular files are supported")
                value = source.read(2 * 1024 * 1024 + 1)
            if len(value) > 2 * 1024 * 1024:
                raise ValueError("File exceeds the 2 MiB limit")
            self.policy.authorize(context)
            return value
        finally:
            os.close(descriptor)

    def write_file(self, context, path, value, *, directory=False):
        if not isinstance(value, bytes) or len(value) > 2 * 1024 * 1024:
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
