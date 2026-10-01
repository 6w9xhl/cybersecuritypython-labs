"""Головний модуль Лабораторної роботи №2 (команди demo та analyze)."""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from labs.lab02.task1 import (
    SESSION_TIMEOUT_SEC,
    Admin,
    Session,
    User,
    UserAccount,
)
from labs.lab02.task2 import analyze_access_log
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"
# Перевірте фактичну назву файлу в архіві lab2_data.zip і за потреби змініть.
DEFAULT_LOG_FILE = Path("labs/lab02/data/data_v01/access.log")
DEFAULT_OUTPUT_FILE = Path("labs/lab02/data/data_v01/web_analysis_report.json")

# функція для презентації роботи ООП-моделей
def run_demo() -> None:
    print("=== Демонстрація Завдання 1 (ООП) ===\n")

    # 1. Створення об'єктів
    print("--- Створення користувача та адміністратора ---")
    user = User(
        username="khrystyna",
        email="khrystyna_kuchma@lpnu.ua",
        password="StrongPass!23",
    )
    admin = Admin(
        username="sec_admin",
        email="admin_sec@lpnu.ua",
        password="AdminSecret#99",
        permissions=["read_logs", "ban_ip"],
    )
    print(f"Створено користувача: {user}")
    print(f"Створено адміністратора: {admin}\n")

    # 2. Зміна email із валідацією
    print("--- Зміна email із валідацією ---")
    user.email = "kuchma_kb201@lpnu.ua"# встановлює правильний емейл
    print(f"Новий валідний email: {user.email}")
    for bad_email in ("wrong_email_format", "a.b@lpnu.ua", "1abc@lpnu.ua"):# перебирає неправильні формати
        try:
            user.email = bad_email#намагаємся їх присвоїти
        except ValueError as exc:
            print(f"Помилка валідації: {exc}")
    print()

    # 3. Права адміністратора
    print("--- Перевірка прав адміністратора ---")
    admin.grant_permission("manage_firewall")#додає нове право
    print(f"Після надання права 'manage_firewall': {admin}")
    print(f"Перевірка has_permission('ban_ip'): {admin.has_permission('ban_ip')}")#перевіряє наявність права
    admin.revoke_permission("ban_ip")#забираєм право
    print(f"Після відкликання 'ban_ip': {admin}")
    print(f"Перевірка has_permission('ban_ip'): {admin.has_permission('ban_ip')}\n")

    # 4. UserAccount: вхід, сесія, таймаут, вихід
    print("--- Робота з UserAccount, сесією та таймаутом ---")
    account = UserAccount(user=user)#ств акаунт 

    fail_login = account.login("khrystyna", "WrongPass123", "192.168.1.15")#спроба входу з неправильним паролем
    print(
        f"Невдалий вхід: result={fail_login}, "
        f"is_authenticated={account.is_authenticated()}"
    )

    ok_login = account.login("khrystyna", "StrongPass!23", "192.168.1.15")#спроба входу з правильним паролем
    print(
        f"Успішний вхід: result={ok_login}, "
        f"is_authenticated={account.is_authenticated()}"
    )
    print(f"Доступ через спецметод account['user']: {account['user']}")

    # зсуває last_activity в минуле
    if account.session is not None:
        account.session.last_activity -= timedelta(seconds=SESSION_TIMEOUT_SEC + 10)# відмотує час активності назад
    print(
        f"Після закінчення таймауту ({SESSION_TIMEOUT_SEC} с): "
        f"is_authenticated={account.is_authenticated()}"# с-ма має вернути фолс
    )

    account.login("khrystyna", "StrongPass!23", "10.0.0.5")#заходим
    account.logout()#виходим
    print(f"Після виходу (logout): is_authenticated={account.is_authenticated()}\n")

    # 5. Захист доступу через __getitem__ / __setitem__
    print("--- Захист __getitem__ / __setitem__ ---")
    try:
        account["password_hash"]#витягує приватний хеш
    except KeyError as exc:#клас має заблочити і викинути кейерор
        print(f"KeyError (заборонений ключ): {exc}")
    try:
        account["session"] = "not a session"#підкидаєм рядок замість об'єкта сешн
    except TypeError as exc:#клас блокує
        print(f"TypeError (хибний тип): {exc}")
    account["session"] = Session(ip="127.0.0.1")#правильне присвоєння
    print(f"Коректне присвоєння account['session']: {account['session']}\n")

    # 6. Журнал аудиту
    print("--- Журнал аудиту ---")
    account.audit_log.show_all()#друкує всі дії(входи, виходи)

    #акаунт без пароля
    print("\n--- Експеримент: користувач без пароля ---")
    # password за замовчуванням None, тому пароль не встановлюється
    ghost_user = User(username="ghost", email="ghost@lpnu.ua")
    ghost_admin = Admin(
        username="ghost_admin",
        email="admin_ghost@lpnu.ua",
        permissions=["read_logs"],
    )
    # акаунт із порожнім журналом, який створюється автоматично
    ghost_account = UserAccount(user=ghost_user)
    print(f"Створено: {ghost_user}")
    print(f"Створено: {ghost_admin}")
    ok_ghost_login = ghost_account.login("ghost", "any_password", "127.0.0.1")
    print(f"Спроба входу без встановленого пароля: {ok_ghost_login}")
    ghost_account.audit_log.show_all()

#функ перевіряє, чи є аргумент + числом
def positive_int(value: str) -> int:
    try:
        number = int(value)#текст перетв на число
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' не є цілим числом") from None
    if number <= 0:
        raise argparse.ArgumentTypeError("значення має бути додатним")
    return number

#функ перевіряє валідність нттп коду
def http_status(value: str) -> int:
    number = positive_int(value)#перевірка чи взагалі + число
    if not 100 <= number <= 599:#перевірка чи входить воно в стандартний діапазон
        raise argparse.ArgumentTypeError("статус-код має бути в межах 100-599")
    return number

#функ перетворює текстовий час у формат дейтатайм
def utc_datetime(value: str) -> datetime:
    try:
        parsed = datetime.strptime(value, DATETIME_FORMAT)#парсимо рядок за шаблоном
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"'{value}' не відповідає формату 'YYYY-MM-DD HH:MM:SS'"
        ) from None
    return parsed.replace(tzinfo=timezone.utc)#додаєм часовий пояс ютс

#функ збирає меню командого рядка
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(#ств головний парсер
        prog="python -m labs.lab02.main",
        description=(
            f"Лабораторна робота №2 | {STUDENT_NAME} ({GROUP_NAME}) | "
            f"Варіант №{VARIANT_NUMBER}"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)#підкоманди демо і аналайз, одна з них обов'язкова

    subparsers.add_parser(#ств команду демо
        "demo",
        help="Запустити демонстрацію моделей ООП (Завдання 1)",#опис команди
    )

    analyze_parser = subparsers.add_parser(#ств команду аналайз
        "analyze",
        help="Аналіз журналу веб-сервера access.log (Завдання 2, Варіант 1)",
    )
    analyze_parser.add_argument(#прапорець --лог-файл
        "--log-file",
        type=Path,#очікує шлях до файлу
        default=DEFAULT_LOG_FILE,#якшо не вказано, берем дефолтний
        help=f"Шлях до файлу access.log (дефолт: {DEFAULT_LOG_FILE})",
    )
    analyze_parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_FILE,
        help=f"Шлях до збереження звіту (дефолт: {DEFAULT_OUTPUT_FILE})",
    )
    analyze_parser.add_argument(
        "--min-status",
        type=http_status,#юзає кастомний фільтр статусів
        default=400,
        help="Мінімальний статус-код помилки, 100-599 (дефолт: 400)",
    )
    analyze_parser.add_argument(
        "--top",
        type=positive_int,#кастомний фільтр для + чисел
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
        type=utc_datetime,#конвертація тексту в час
        default=None,
        help="Початок інтервалу у форматі 'YYYY-MM-DD HH:MM:SS' (UTC)",
    )
    analyze_parser.add_argument(
        "--end-time",
        type=utc_datetime,
        default=None,
        help="Кінець інтервалу у форматі 'YYYY-MM-DD HH:MM:SS' (UTC)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    parser = build_parser()#отримує меню
    args = parser.parse_args(argv)#зчитує те, що ввели в консолі

    if args.command == "demo":#якшо викликали команду демо
        run_demo()#презентація ооп
        return 0

    if args.command == "analyze":
        if args.start_time and args.end_time and args.start_time > args.end_time:#чи не перепутали початок і кінець
            print(
                "[ERROR] --start-time не може бути пізніше за --end-time",
                file=sys.stderr,
            )
            return 1
        try:#спроба запустити аналіз
            analyze_access_log(#виклик функ з таск2.пай передаючи їй всі зчитані аргументи
                log_file=args.log_file,
                output_file=args.output,
                min_status=args.min_status,
                top_n=args.top,
                report_format=args.format,
                start_time=args.start_time,
                end_time=args.end_time,
            )
        except (OSError, ValueError, TypeError) as exc:
            # OSError охоплює FileNotFoundError та PermissionError
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 1
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())