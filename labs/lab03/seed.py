"""Початкове заповнення бази навчальними даними з data/seed.json.

Запуск: python -m labs.lab03.seed
"""

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from labs.lab03.config import VALUE_MAX, VALUE_MIN
from labs.lab03.database import get_connection, initialize_database

BASE_DIR = Path(__file__).resolve().parent
SEED_DATA_PATH = BASE_DIR / "data" / "seed.json"

# допустимі статуси (використовує validate_seed_data)
ALLOWED_STATUSES = {"new", "in_progress", "done"}


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


# validate_seed_data() — ручна перевірка seed.json
# Повертає текст помилки або None, якщо дані коректні
def validate_seed_data(data: Any) -> str | None:
    """Перевірити структуру й значення seed.json; повернути текст помилки або None."""
    if not isinstance(data, dict):
        return "коренем seed.json має бути JSON-об'єкт."
    categories = data.get("categories")
    # беремо масив записів
    records = data.get("records")
    if not isinstance(categories, list) or len(categories) != 3:
        return "seed.json має містити рівно 3 категорії."
    if not isinstance(records, list) or len(records) != 8:
        return "seed.json має містити рівно 8 записів."

    category_ids: set[int] = set()
    category_names: set[str] = set()

    for cat in categories:
        # категорія має бути словником і містити ключі id та name
        if not isinstance(cat, dict) or not {"id", "name"}.issubset(cat):
            return "некоректна структура категорії (потрібні id та name)."
        if not _is_int(cat["id"]) or cat["id"] <= 0:
            return f"id категорії має бути додатним цілим: {cat['id']!r}."
        if not isinstance(cat["name"], str) or not 2 <= len(cat["name"].strip()) <= 40:
            return f"назва категорії має містити 2-40 символів: {cat['name']!r}."
        if cat["id"] in category_ids or cat["name"] in category_names:
            return f"дублікат категорії: {cat['name']!r}."
        # запам'ятовуємо id та назви цієї категорії
        category_ids.add(cat["id"])
        category_names.add(cat["name"])
    # множина кодів записів, які вже зустрілися (перевірка унікальності code)
    codes: set[str] = set()
    # перебираємо кожен запис
    for rec in records:
        # набір обов'язкових ключів кожного запису
        required = {"code", "title", "category_id", "value", "status"}
        # запис має бути словником і містити всі обов'язкові ключі
        if not isinstance(rec, dict) or not required.issubset(rec):
            return "некоректна структура запису (потрібні code, title, category_id, value, status)."
        if "id" in rec:
            return "запис у seed.json не повинен містити id."
        if not isinstance(rec["code"], str) or not 3 <= len(rec["code"].strip()) <= 40:
            return f"code має містити 3-40 символів: {rec['code']!r}."
        if not isinstance(rec["title"], str) or not 3 <= len(rec["title"].strip()) <= 120:
            return f"title має містити 3-120 символів у записі {rec['code']!r}."
        if rec["code"] in codes:
            return f"дублікат code у seed.json: {rec['code']!r}."
        codes.add(rec["code"])
        if rec["category_id"] not in category_ids:
            return f"запис {rec['code']!r} посилається на неіснуючу категорію."
        if not _is_number(rec["value"]) or not VALUE_MIN <= rec["value"] <= VALUE_MAX:
            return f"value поза межами {VALUE_MIN}-{VALUE_MAX} у записі {rec['code']!r}."
        if rec["status"] not in ALLOWED_STATUSES:
            return f"недопустимий статус у записі {rec['code']!r}: {rec['status']!r}."
    return None


# seed_database() — головна функція заповнення
# Порядок: файл є - JSON прочитано - дані валідні - база порожня - вставка
def seed_database() -> None:
    """Заповнити порожню базу початковими даними в одній транзакції."""
    if not SEED_DATA_PATH.exists():
        print(f"Помилка: файл {SEED_DATA_PATH} не знайдено.")
        return

    try:
        with SEED_DATA_PATH.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Не вдалося прочитати seed.json: {exc}")
        return
    # Крок 1: перевірка даних ДО звернення до бази
    error = validate_seed_data(data)
    if error:
        print(f"Помилка в seed.json: {error}")
        return

    categories = data["categories"]
    records = data["records"]

    try:
        # Таблиці створюються до транзакції заповнення, наявні дані не змінюються
        # Крок 2: створити таблиці (ДО транзакції вставки)
        initialize_database()

        with closing(get_connection()) as connection:
            with connection:
                categories_count = connection.execute("SELECT COUNT(*) FROM categories").fetchone()[
                    0
                ]
                records_count = connection.execute("SELECT COUNT(*) FROM records").fetchone()[0]
                # Крок 3: база вже має дані → нічого не змінюємо (повтор безпечний)
                if categories_count > 0 or records_count > 0:
                    print("База вже містить дані. Заповнення скасовано, щоб уникнути дублікатів.")
                    return
                # Крок 4: вставка категорій (id з JSON), потім записів (id створює база)
                # [SQL-ІН'ЄКЦІЯ] значення передаються через «?», а не в тексті SQL
                connection.executemany(
                    "INSERT INTO categories (id, name) VALUES (?, ?)",
                    [(cat["id"], cat["name"].strip()) for cat in categories],
                )
                connection.executemany(
                    """
                    INSERT INTO records (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            rec["code"].strip(),
                            rec["title"].strip(),
                            rec["category_id"],
                            rec["value"],
                            rec["status"],
                        )
                        for rec in records
                    ],
                )
        print(f"Успішно додано {len(categories)} категорії та {len(records)} записів.")
    except sqlite3.IntegrityError as exc:
        print(f"Помилка цілісності даних, пакет скасовано: {exc}")
    except sqlite3.Error as exc:
        print(f"Помилка бази даних під час заповнення, пакет скасовано: {exc}")


if __name__ == "__main__":
    seed_database()
