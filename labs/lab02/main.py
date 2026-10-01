"""Головний модуль Лабораторної роботи №2 (команди demo та analyze)."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from labs.lab02.task1 import (
    SESSION_TIMEOUT_SEC,
    Admin,
    User,
    UserAccount,
)
from labs.lab02.task2 import analyze_access_log
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def run_demo() -> None:
    """Демонстрація роботи класів Завдання 1."""
    print("=== Демонстрація Завдання 1 (ООП) ===\n")

    user = User(
        username="khrystyna",
        email="khrystyna.kuchma@lpnu.ua",
        password="StrongPass!23",
    )
    admin = Admin(
        username="sec_admin",
        email="admin.sec@lpnu.ua",
        password="AdminSecret#99",
        permissions=["read_logs", "ban_ip"],
    )
    # юзер без пароля
    ghost_user = User(
        username="ghost",
        email="ghost@lpnu.ua",
        # password: str | None = None він автоматично стає None
    )
    # адмін без пароля
    ghost_admin = Admin(
        username="ghost_admin", email="admin.ghost@lpnu.ua", permissions=["read_logs"]
    )
    # ак з пустим логом
    ghost_account = UserAccount(user=ghost_user)
    print("\n--- Експеримент: Користувачі без пароля ---")
    print(f"Створено: {ghost_user}")
    print(f"Створено: {ghost_admin}")

    # Перевірка, чи заблокує система вхід для акаунта без пароля
    ok_ghost_login = ghost_account.login("ghost", "any_password", "127.0.0.1")
    print(f"Спроба входу без встановленого пароля: {ok_ghost_login}")

    print(f"Створено користувача: {user}")
    print(f"Створено адміністратора: {admin}\n")

    print("--- Зміна email із валідацією ---")
    user.email = "kuchma.kb201@lpnu.ua"
    print(f"Новий валідний email: {user.email}")
    try:
        user.email = "wrong_email_format"
    except ValueError as exc:
        print(f"Помилка валідації невалідного email: {exc}\n")

    print("--- Перевірка прав адміністратора ---")
    admin.grant_permission("manage_firewall")
    print(f"Після надання права 'manage_firewall': {admin}")
    print(f"Перевірка has_permission('ban_ip'): {admin.has_permission('ban_ip')}")
    admin.revoke_permission("ban_ip")
    print(f"Після відкликання 'ban_ip': {admin}\n")

    print("--- Робота з UserAccount, сесією та таймаутом ---")
    account = UserAccount(user=user)

    fail_login = account.login("khrystyna", "WrongPass123", "192.168.1.15")
    print(
        f"Невдалий вхід: result={fail_login}, "
        f"is_authenticated={account.is_authenticated()}"
    )

    ok_login = account.login("khrystyna", "StrongPass!23", "192.168.1.15")
    print(
        f"Успішний вхід: result={ok_login}, "
        f"is_authenticated={account.is_authenticated()}"
    )
    print(f"Доступ через спецметод account['user']: {account['user']}")

    if account.session is not None:
        account.session.last_activity -= timedelta(seconds=SESSION_TIMEOUT_SEC + 10)
    print(
        f"Після закінчення таймауту ({SESSION_TIMEOUT_SEC} с): "
        f"is_authenticated={account.is_authenticated()}"
    )

    account.login("khrystyna", "StrongPass!23", "10.0.0.5")
    account.logout()
    print(f"Після виходу (logout): is_authenticated={account.is_authenticated()}\n")

    account.audit_log.show_all()


def build_parser() -> argparse.ArgumentParser:
    """Створює парсер аргументів командного рядка для режимів demo та analyze."""
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab02.main",
        description=(
            f"Лабораторна робота №2 | {STUDENT_NAME} ({GROUP_NAME}) | "
            f"Варіант №{VARIANT_NUMBER}"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "demo",
        help="Запустити демонстрацію моделей ООП (Завдання 1)",
    )

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Аналіз журналу веб-сервера access.log (Завдання 2, Варіант 1)",
    )
    analyze_parser.add_argument(
        "--log-file",
        type=Path,
        default=Path("labs/lab02/data/access.log"),
        help="Шлях до файлу access.log",
    )
    analyze_parser.add_argument(
        "--output",
        type=Path,
        default=Path("labs/lab02/data/web_analysis_report.json"),
        help="Шлях до збереження звіту",
    )
    analyze_parser.add_argument(
        "--min-status",
        type=int,
        default=400,
        help="Мінімальний статус-код помилки (дефолт: 400)",
    )
    analyze_parser.add_argument(
        "--top",
        type=int,
        default=5,
        help="Кількість топ IP-адрес із помилками (дефолт: 5)",
    )
    analyze_parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Формат вихідного звіту: json або csv (дефолт: json)",
    )
    analyze_parser.add_argument(
        "--start-time",
        type=str,
        default=None,
        help="Початок інтервалу у форматі 'YYYY-MM-DD HH:MM:SS'",
    )
    analyze_parser.add_argument(
        "--end-time",
        type=str,
        default=None,
        help="Кінець інтервалу у форматі 'YYYY-MM-DD HH:MM:SS'",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Точка входу CLI-програми."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "demo":
        run_demo()
        return 0

    if args.command == "analyze":
        try:
            start_dt = (
                datetime.strptime(args.start_time, "%Y-%m-%d %H:%M:%S").replace(
                    tzinfo=timezone.utc
                )
                if args.start_time
                else None
            )
            end_dt = (
                datetime.strptime(args.end_time, "%Y-%m-%d %H:%M:%S").replace(
                    tzinfo=timezone.utc
                )
                if args.end_time
                else None
            )
            analyze_access_log(
                log_file=args.log_file,
                output_file=args.output,
                min_status=args.min_status,
                top_n=args.top,
                report_format=args.format,
                start_time=start_dt,
                end_time=end_dt,
            )
        except (FileNotFoundError, ValueError) as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 1
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
