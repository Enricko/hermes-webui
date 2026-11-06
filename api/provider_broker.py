"""Tool-free managed inference. No agent imports, tools or arbitrary URL proxy.

Credentials stay in a private service-side vault; a member chooses only granted
connection/model IDs. Subscription refresh/native Agent replay is intentionally
not implemented here; this mode supports API-key OpenAI-compatible and native
Anthropic chat, and never claims full Agent isolation.
"""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request

from api.access_policy import AccessContext, PolicyUnavailable

_VAULT_LOCK = threading.RLock()


class ProviderFailure(RuntimeError):
    pass


class CredentialVault:
    def __init__(self, path: Path):
        self.path = Path(path)

    def _read(self):
        if not self.path.exists():
            return {}
        fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, encoding="utf-8") as source:
            if os.name != "nt" and os.fstat(source.fileno()).st_mode & 0o077:
                raise PolicyUnavailable("Credential vault permissions must be private")
            data = json.load(source)
            if not isinstance(data, dict):
                raise PolicyUnavailable("Credential vault is invalid")
            return data

    @staticmethod
    def _binding(binding):
        return hashlib.sha256(json.dumps(binding, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()

    def get(self, connection_id: str, binding: dict) -> str:
        with _VAULT_LOCK:
            value = self._read().get(connection_id)
            if not isinstance(value, dict) or value.get("binding") != self._binding(binding) or not value.get("token"):
                raise ProviderFailure("Provider credential is not configured")
            return value["token"]

    @staticmethod
    def validate_credential(credential):
        if not isinstance(credential, str) or not 1 <= len(credential) <= 16384 or any(c in credential for c in "\r\n\0"):
            raise ValueError("Invalid credential")

    def put(self, connection_id: str, credential: str, binding: dict):
        from api.access_policy import _id
        _id(connection_id)
        self.validate_credential(credential)
        with _VAULT_LOCK:
            self.path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            # Inter-process serialization prevents concurrent admin writes from
            # losing another connection. Read/replace are inside the same lock.
            with self.path.with_name(self.path.name + ".lock").open("a+b") as lock:
                if os.name != "nt":
                    import fcntl
                    fcntl.flock(lock, fcntl.LOCK_EX)
                else:
                    raise PolicyUnavailable("Credential administration requires a verified locking backend")
                data = self._read()
                data[connection_id] = {"token": credential, "binding": self._binding(binding)}
                fd, temporary = tempfile.mkstemp(dir=self.path.parent, prefix=".credentials-")
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as output:
                        json.dump(data, output)
                        output.flush()
                        os.fsync(output.fileno())
                    os.chmod(temporary, 0o600)
                    os.replace(temporary, self.path)
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_connection(binding: dict):
    protocol = binding.get("protocol", "openai")
    if protocol not in {"openai", "anthropic"}:
        raise ValueError("Tool-free chat supports openai or anthropic API-key connections")
    endpoint = urllib.parse.urlsplit(str(binding.get("base_url") or ""))
    if endpoint.scheme not in {"https", "http"} or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
        raise ValueError("A trusted HTTP(S) provider base URL is required")
    if not isinstance(binding.get("account_id"), str) or not binding["account_id"].strip():
        raise ValueError("Connection requires an upstream account identity")


def infer(store, vault: CredentialVault, context: AccessContext, messages: list[dict], *, max_tokens=4096) -> tuple[str, object]:
    admission, resources = store.context_resources(context)
    connection = resources[context.connection_id]
    validate_connection(connection)
    credential = vault.get(context.connection_id, connection)
    prompt = str(resources[context.profile_id].get("system_prompt") or "You are a helpful assistant.")
    for skill in context.skills:
        prompt += "\n\n" + str(resources[skill].get("content") or "")
    protocol = connection.get("protocol", "openai")
    base = connection["base_url"].rstrip("/")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if protocol == "anthropic":
        # Native Messages; tool execution and arbitrary client headers are absent.
        target = base + ("/messages" if base.endswith("/v1") else "/v1/messages")
        payload = {"model": context.model, "system": prompt, "messages": messages, "max_tokens": max_tokens}
        headers.update({"x-api-key": credential, "anthropic-version": "2023-06-01"})
    else:
        target = base + "/chat/completions"
        payload = {"model": context.model, "messages": [{"role": "system", "content": prompt}, *messages],
                   "max_tokens": max_tokens, "stream": False}
        headers["Authorization"] = "Bearer " + credential
    # No ambient proxy/netrc configuration and no redirect credential forwarding.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(target, data=json.dumps(payload).encode(), headers=headers, method="POST")
    store.revalidate(admission)
    try:
        with opener.open(request, timeout=90) as response:
            raw = response.read(8 * 1024 * 1024 + 1)
            if len(raw) > 8 * 1024 * 1024:
                raise ProviderFailure("Provider response exceeded the limit")
            result = json.loads(raw)
        if protocol == "anthropic":
            text = "".join(item.get("text", "") for item in result["content"] if item.get("type") == "text")
        else:
            text = result["choices"][0]["message"]["content"]
        if not isinstance(text, str):
            raise ProviderFailure("Provider returned no text response")
    except (urllib.error.URLError, OSError, ValueError, KeyError, IndexError, TypeError):
        # Upstream response/error bodies may contain credentials. Never reflect them.
        raise ProviderFailure("Provider request failed; check the managed connection") from None
    store.revalidate(admission)
    return text, admission
