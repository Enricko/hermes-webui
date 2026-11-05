#!/usr/bin/env python3
"""Manage WebUI login accounts with roles (local patch, see api/user_roles.py).

    webui_users.py list
    webui_users.py add admin1 --role admin
    webui_users.py add alice --role user --profile team-alice --workspace /srv/workspaces/alice
    webui_users.py passwd alice
    webui_users.py remove alice

Passwords are always prompted (never taken from argv). Changes apply on the next
request — no restart needed. Removing an account or changing its role/profile
logs out its existing sessions.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.user_roles import (  # noqa: E402
    ROLE_USER,
    ROLES,
    _PROFILE_RE,
    _USERNAME_RE,
    hash_password,
    normalize_username,
)


def default_users_file() -> Path:
    override = os.getenv("HERMES_WEBUI_USERS_FILE", "").strip()
    if override:
        return Path(override).expanduser()
    state = os.getenv("HERMES_WEBUI_STATE_DIR", "").strip()
    if state:
        return Path(state).expanduser() / "users.json"
    home = os.getenv("HERMES_HOME", "").strip() or "~/.hermes"
    return Path(home).expanduser() / "webui" / "users.json"


def read(path: Path) -> dict:
    if not path.exists():
        return {"users": {}}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("users"), dict):
        sys.exit(f"{path}: unexpected format (want {{\"users\": {{...}}}})")
    return data


def write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".users.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.chmod(tmp, 0o600)
        path.with_name(path.name + ".required").touch(mode=0o600, exist_ok=True)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def prompt_password(username: str) -> str:
    while True:
        pw = getpass.getpass(f"Password for {username}: ")
        if len(pw) < 8:
            print("Use at least 8 characters.", file=sys.stderr)
            continue
        if getpass.getpass("Repeat password: ") != pw:
            print("Passwords do not match.", file=sys.stderr)
            continue
        return pw


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", type=Path, default=None, help="users.json path (default: STATE_DIR/users.json)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    add = sub.add_parser("add", help="create or update an account (prompts for a password if new)")
    add.add_argument("username")
    add.add_argument("--role", choices=ROLES, required=True)
    add.add_argument("--profile", help="profile the account is locked to (role user)")
    add.add_argument("--workspace", action="append", default=[], help="allowed workspace root (role user, repeatable)")
    pw = sub.add_parser("passwd")
    pw.add_argument("username")
    rm = sub.add_parser("remove")
    rm.add_argument("username")
    for action in ("disable", "enable"):
        command = sub.add_parser(action)
        command.add_argument("username")
    args = ap.parse_args()

    path = args.file or default_users_file()
    data = read(path)
    users = data["users"]

    if args.cmd == "list":
        if not users:
            print(f"No accounts in {path}")
        for name, rec in sorted(users.items()):
            extra = ""
            if rec.get("role") == ROLE_USER:
                extra = f"  profile={rec.get('profile')}  workspaces={', '.join(rec.get('workspaces') or [])}"
            print(f"{name:20} {rec.get('role')}{extra}")
        return

    username = normalize_username(args.username)
    if not _USERNAME_RE.fullmatch(username):
        sys.exit("Username: lowercase letters, digits, '.', '_' or '-' (max 64).")

    if args.cmd == "remove":
        if users.pop(username, None) is None:
            sys.exit(f"No account {username!r}")
        write(path, data)
        print(f"Removed {username}; its sessions are logged out.")
        return

    if args.cmd == "passwd":
        if username not in users:
            sys.exit(f"No account {username!r}")
        users[username]["password"] = hash_password(prompt_password(username))
        write(path, data)
        print(f"Password updated for {username}.")
        return

    if args.cmd in ("disable", "enable"):
        if username not in users:
            sys.exit(f"No account {username!r}")
        users[username]["disabled"] = args.cmd == "disable"
        # Reactivation must not resurrect old cookies.
        users[username]["auth_generation"] = int(users[username].get("auth_generation", 0)) + 1
        write(path, data)
        print(f"Account {username}: {args.cmd}d.")
        return

    # add / update
    rec = dict(users.get(username) or {})
    rec.setdefault("id", secrets.token_hex(16))
    rec["role"] = args.role
    if args.role == ROLE_USER:
        profile = (args.profile or rec.get("profile") or "").strip()
        if not (profile == "default" or _PROFILE_RE.fullmatch(profile)):
            sys.exit("--profile is required for role user (an existing profile name).")
        workspaces = [str(Path(w).expanduser().resolve()) for w in args.workspace] or list(rec.get("workspaces") or [])
        if not workspaces:
            sys.exit("--workspace is required for role user.")
        for w in workspaces:
            if not Path(w).is_dir():
                sys.exit(f"Workspace {w} is not an existing directory.")
        home = Path(os.getenv("HERMES_HOME", "").strip() or "~/.hermes").expanduser()
        if profile != "default" and not (home / "profiles" / profile).is_dir():
            print(f"Warning: profile {profile!r} not found under {home / 'profiles'}", file=sys.stderr)
        rec["profile"] = profile
        rec["workspaces"] = workspaces
    else:
        rec.pop("profile", None)
        rec.pop("workspaces", None)
    if "password" not in rec:
        rec["password"] = hash_password(prompt_password(username))
    users[username] = rec
    write(path, data)
    print(f"Saved {username} ({args.role}) in {path}")


if __name__ == "__main__":
    main()
