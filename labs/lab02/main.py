"""Точка входу ЛР №2.

Команди (запускати з кореня репозиторію):
    python -m labs.lab02.main demo
    python -m labs.lab02.main analyze \
        --rules-file labs/lab02/data/data_v03/firewall_rules.json
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import timedelta

from labs.lab02 import task2
from labs.lab02.task1 import (
    SESSION_TIMEOUT_SEC,
    Admin,
    AuditLog,
    User,
    UserAccount,
    utc_now,
)

# Демонстраційні облікові дані (навчальні, не реальні).
DEMO_USERNAME = "alice_dev"
DEMO_PASSWORD = "S3cure!Pass-2026"
DEMO_IP = "192.168.1.10"


def _section(title: str) -> None:
    print(f"\n=== {title} ===")


def run_demo(_args: argparse.Namespace | None = None) -> int:
    """Демонстрація Завдання 1: вхід, email, права адміна, таймаут, вихід, аудит."""
    log = AuditLog()
    user = User(DEMO_USERNAME, "alice_dev@example.com", DEMO_PASSWORD)
    account = UserAccount(user, audit_log=log)

    _section("1. Login: failure, then success")
    print(
        "wrong password   ->", account.login(DEMO_USERNAME, "wrong-password", DEMO_IP)
    )
    print("authenticated    ->", account.is_authenticated())
    print("correct password ->", account.login(DEMO_USERNAME, DEMO_PASSWORD, DEMO_IP))
    print("authenticated    ->", account.is_authenticated())
    print(user)

    _section("2. Email change with validation")
    candidates = (
        "alice_new@example.com",  # коректний
        "alice@corp.example.com",  # коректний, піддомен
        "1alice@example.com",  # починається з цифри
        "al@example.com",  # локальна частина коротша за 3 символи
        "alice-dev@example.com",  # дефіс не дозволений
        "alice@localhost",  # домен без крапки
    )
    for candidate in candidates:
        try:
            user.email = candidate
            print(f"OK       {candidate}")
        except ValueError as exc:
            print(f"REJECTED {candidate}  ({exc})")
    print("current email:", user.email)

    _section("3. Administrator permissions")
    admin = Admin("root_admin", "root_admin@example.com", "Adm1n!Pass-2026")
    admin.grant_permission("read_logs")
    admin.grant_permission("manage_users")
    print(admin)
    print("is a User              :", isinstance(admin, User))
    print("has manage_users       :", admin.has_permission("manage_users"))
    admin.revoke_permission("manage_users")
    print("after revoke, has it   :", admin.has_permission("manage_users"))
    print(admin)

    _section("4. Session timeout")
    later = utc_now() + timedelta(seconds=SESSION_TIMEOUT_SEC + 1)
    print(
        f"authenticated {SESSION_TIMEOUT_SEC + 1} s later ->",
        account.is_authenticated(now=later),
    )
    print("session after timeout    ->", account["session"])

    _section("5. Login again, then logout")
    print("login  ->", account.login(DEMO_USERNAME, DEMO_PASSWORD, DEMO_IP))
    print("logout ->", account.logout())
    print("logout again (no session) ->", account.logout())

    _section("6. Deactivated user cannot log in")
    user.deactivate()
    print(
        "login with correct password ->",
        account.login(DEMO_USERNAME, DEMO_PASSWORD, DEMO_IP),
    )

    _section("7. Dict-style access to UserAccount")
    print('account["user"] ->', account["user"])
    for key in ("password_hash", "_User__password_hash"):
        try:
            account[key]
        except KeyError as exc:
            print(f"account[{key!r}] -> KeyError {exc}")
    try:
        account["user"] = "alice"
    except TypeError as exc:
        print("account['user'] = 'alice' -> TypeError:", exc)

    _section("8. Audit log")
    account.audit_log.show_all()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab02.main",
        description="Lab 2: OOP user model (demo), firewall rules auditor (analyze).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    demo = subparsers.add_parser("demo", help="run the Task 1 demonstration")
    demo.set_defaults(handler=run_demo)

    analyze = subparsers.add_parser(
        "analyze", help="audit a firewall rules file (Task 2, variant 3)"
    )
    task2.add_arguments(analyze)
    analyze.set_defaults(handler=task2.run)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
