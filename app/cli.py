"""Small admin CLI: change the password without editing the database by hand."""

from __future__ import annotations

import argparse
import getpass
import sys

from .config import load_settings
from .db import Database
from .security import hash_password


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    set_password = sub.add_parser("set-password", help="change an account password")
    set_password.add_argument("--username", help="defaults to CYBERLAB_ADMIN_USERNAME")
    set_password.add_argument("--stdin", action="store_true", help="read password from stdin")

    args = parser.parse_args()
    settings = load_settings()
    db = Database(settings.data_dir / "cyberlab.db")

    if args.command == "set-password":
        username = args.username or settings.admin_username
        if args.stdin:
            password = sys.stdin.readline().rstrip("\n")
        else:
            password = getpass.getpass("New password: ")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("Passwords do not match.", file=sys.stderr)
                return 1
        if len(password) < 12:
            print("Password must be at least 12 characters.", file=sys.stderr)
            return 1
        if not db.set_password(username, hash_password(password)):
            print(f"No such user: {username}", file=sys.stderr)
            return 1
        db.audit(username, "admin.password_changed", "via cli", "local")
        print(f"Password updated for {username}.")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
