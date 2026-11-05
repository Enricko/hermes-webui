#!/usr/bin/env python3
"""Manage explicit multi-user grants without touching agent state or secrets.

The configured account store supplies immutable identities. The JSON policy
input contains registered resource IDs, labels, bindings and model allowlists;
never pass provider credentials. This initializes policy only, not a runtime.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.access_policy import AccessDenied, PolicyStore, PolicyUnavailable  # noqa: E402
from api.user_roles import load_users, normalize_username  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default=os.getenv("HERMES_WEBUI_ACCESS_POLICY_FILE"), required=False)
    parser.add_argument("--admin", required=True, help="existing local administrator username")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    commands.add_parser("show")
    account = commands.add_parser("account", help="register an existing local login identity")
    account.add_argument("username")
    account.add_argument("--disable", action="store_true")
    resource = commands.add_parser("resource", help="register metadata from a JSON file")
    resource.add_argument("json_file", type=Path)
    grants = commands.add_parser("grants", help="replace one account's grants from a JSON file")
    grants.add_argument("username")
    grants.add_argument("json_file", type=Path)
    args = parser.parse_args()
    if not args.policy:
        parser.error("--policy or HERMES_WEBUI_ACCESS_POLICY_FILE is required")
    accounts = load_users()
    admin = accounts.get(normalize_username(args.admin))
    if not admin or admin["role"] != "admin" or not admin.get("id"):
        parser.error("Administrator needs an immutable ID; update it with webui_users.py add first")
    try:
        if args.command == "init":
            PolicyStore.initialize(args.policy, admin["id"])
            print("Initialized policy. Isolated runtime admission is not enabled.")
            return
        store = PolicyStore(args.policy)
        if args.command == "show":
            print(json.dumps(store.snapshot(admin["id"]), indent=2))
            return
        if args.command in {"account", "grants"}:
            user = accounts.get(normalize_username(args.username))
            if not user or not user.get("id"):
                parser.error("Account must exist and have an immutable ID")
            if args.command == "account":
                store.put_account(admin["id"], user["id"], role=user["role"], enabled=not args.disable)
            else:
                store.replace_grants(admin["id"], user["id"], json.loads(args.json_file.read_text()))
        elif args.command == "resource":
            data = json.loads(args.json_file.read_text())
            store.put_resource(admin["id"], data["id"], kind=data["kind"], label=data["label"], binding=data["binding"])
        print("Policy updated.")
    except (AccessDenied, PolicyUnavailable, ValueError, OSError, KeyError, TypeError) as exc:
        parser.exit(1, f"Policy operation refused: {type(exc).__name__}\n")


if __name__ == "__main__":
    main()
