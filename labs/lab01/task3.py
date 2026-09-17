import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import VARIANT_NUMBER

MIN_PASSWORD_LENGTH = 12
PERSONAL_SALT = str(VARIANT_NUMBER).zfill(5)

# шляхи до папки data та файлів
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
CSV_FILE = os.path.join(DATA_DIR, "users.csv")
LOG_FILE = os.path.join(DATA_DIR, "log.json")


# створення власного винятку
class ValidationError(Exception):
    pass


# функція безпечного хешування Варік 1: sha3_512
def generate_hash(password: str, salt: str = "00000") -> str:
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль надто короткий. Мінімум {MIN_PASSWORD_LENGTH} символів."
        )

    # конкатенація пароля та солі
    salted_password = password + salt
    return hashlib.sha3_512(
        salted_password.encode("utf-8")
    ).hexdigest()  # тескт байти,пережовує і назад в 16


# декоратор для логування подій у JSON. перехоплює процес авторизації
def log_event(func):
    def wrapper(username, password):
        result_status = "failure"
        try:
            res = func(username, password)
            if res:
                result_status = "success"
            return res
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "args": [username, "*" * len(password)],
                "kwargs": {},
            }

            os.makedirs(DATA_DIR, exist_ok=True)
            logs = []

            # читаємо існуючі логи, якщо файл є
            if os.path.exists(LOG_FILE):
                try:
                    with open(LOG_FILE, mode="r", encoding="utf-8") as lf:
                        logs = json.load(lf)
                except (OSError, json.JSONDecodeError):
                    pass

            logs.append(log_entry)

            # запис оновленого списку логів
            try:
                with (
                    open(LOG_FILE, mode="w", encoding="utf-8") as lf
                ):  # якшо файл є, відкриває його і зчитує стару історію в змінну logs
                    json.dump(
                        logs, lf, indent=4, ensure_ascii=False
                    )  # відкриває файл на перезапис і зберігає туди весь оновлений список logs
            except OSError:
                pass

    return wrapper


# функції реєстрації. перетворення пароль на хеш
def create_user(username, password):
    hash_value = generate_hash(password, PERSONAL_SALT)
    return (username, hash_value)


def create_users(users_list):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CSV_FILE, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["username", "password_hash"])
        for u, p in users_list:
            writer.writerow(create_user(u, p))


# функція авторизації
@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Логін або пароль порожні")

    with (
        open(CSV_FILE, mode="r", encoding="utf-8") as f
    ):  # читає CSV-файл і перетворює його на список словників,де ключі це заголовки
        reader = csv.DictReader(f)
        users_db = list(reader)

    input_hash = generate_hash(password, PERSONAL_SALT)  # хешує пароль, який ввів юзер

    for user in users_db:
        if user["username"] == username and user["password_hash"] == input_hash:
            return True
    return False


# головна функція
def main():
    print(f"Персональна сіль: '{PERSONAL_SALT}'\n")

    # кортеж із 10 користувачів паролі >= 12 символів
    users_to_register = (
        ("khrystyna", "MySecurePass2026!"),
        ("marta", "MathTutoring2026!"),
        ("taras", "LabNetworkConfig1!"),
        ("maksym", "SecurityAuditISO1!"),
        ("admin", "SuperSecretPass123!"),
        ("guest1", "GuestPassword123!"),
        ("user2", "AnotherValidPass!"),
        ("user3", "ValidPassword123!"),
        ("user4", "StrongPassword12!"),
        ("user5", "CyberSecurity2026!"),
    )

    try:
        print("Створення бази користувачів")
        create_users(users_to_register)
        print("Базу успішно створено (users.csv)\n")

        print("Зміст бази даних:")
        with open(CSV_FILE, mode="r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
            print(f"{header[0]:<15} | {header[1]}")
            print("-" * 80)
            for row in reader:
                print(f"{row[0]:<15} | {row[1]}")
        print("-" * 80 + "\n")

        print("Тестування системи авторизації:")
        test_cases = [
            ("khrystyna", "MySecurePass2026!"),  # правильний пароль
            ("marta", "WrongPass123456!"),  # неправильний пароль
            ("hacker", "SomePass123456!"),  # юзера не існує
        ]

        for u, p in test_cases:
            try:
                res = login(u, p)
                status = "ДОЗВОЛЕНО" if res else "ВІДМОВЛЕНО"
                print(f"Вхід для '{u}': {status}")
            except (ValueError, ValidationError) as e:
                print(f"Помилка входу для '{u}': {e}")

        print("\nУсі спроби входу записано у файл log.json")

    except (OSError, FileNotFoundError, PermissionError) as e:
        print(f"Помилка доступу до файлу: {e}")
    except ValidationError as e:
        print(f"Помилка валідації: {e}")
    except ValueError as e:
        print(f"Некоректне значення: {e}")


if __name__ == "__main__":
    main()
