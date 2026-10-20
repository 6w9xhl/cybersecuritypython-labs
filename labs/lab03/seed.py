import json
import sqlite3
from contextlib import closing
from pathlib import Path

from labs.lab03.database import get_connection

BASE_DIR = Path(__file__).resolve().parent
SEED_DATA_PATH = BASE_DIR / "data" / "seed.json"


def seed_database() -> None:
    """Заповнює базу даних початковими даними з seed.json в одній транзакції."""
    if not SEED_DATA_PATH.exists():
        print(f"Помилка: Файл {SEED_DATA_PATH} не знайдено.")
        return

    # Читаємо дані з JSON-файлу
    # Читаємо дані з JSON-файлу
    try:
        with SEED_DATA_PATH.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Не вдалося прочитати seed.json: {exc}")
        return

    if not isinstance(data, dict):
        print("Помилка: коренем seed.json має бути JSON-об'єкт.")
        return

    categories = data.get("categories")
    records = data.get("records")

    if (
        not isinstance(categories, list)
        or len(categories) != 3
        or not isinstance(records, list)
        or len(records) != 8
    ):
        print("Помилка: seed.json має містити 3 категорії та 8 записів.")
        return

    required_category_keys = {"id", "name"}
    required_record_keys = {
        "code",
        "title",
        "category_id",
        "value",
        "status",
    }

    if any(
        not isinstance(item, dict) or not required_category_keys.issubset(item)
        for item in categories
    ):
        print("Помилка: некоректна структура категорій у seed.json.")
        return

    if any(
        not isinstance(item, dict) or not required_record_keys.issubset(item) for item in records
    ):
        print("Помилка: некоректна структура записів у seed.json.")
        return

    with closing(get_connection()) as connection:
        try:
            # Починаємо транзакцію для пакета змін
            with connection:
                # 1. Перевіряємо, чи база вже заповнена (чи існують категорії)
                cursor = connection.execute("SELECT COUNT(*) FROM categories")
                if cursor.fetchone()[0] > 0:
                    print("База вже містить дані. Заповнення скасовано, щоб уникнути дублікатів.")
                    return

                # 2. Додаємо категорії (id, name)
                connection.executemany(
                    "INSERT INTO categories (id, name) VALUES (?, ?)",
                    [(cat["id"], cat["name"]) for cat in categories],
                )

                # 3. Додаємо записи (без id, бо база генерує його сама)
                # Використовуємо параметризовані запити (?) для захисту від ін'єкцій
                records_values = [
                    (
                        rec["code"],
                        rec["title"],
                        rec["category_id"],
                        rec["value"],
                        rec["status"],
                    )
                    for rec in records
                ]
                connection.executemany(
                    """
                    INSERT INTO records (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    records_values,
                )

            print(f"Успішно додано {len(categories)} категорії та {len(records)} записів.")

        except sqlite3.IntegrityError as e:
            # Транзакція автоматично скасовується контекстним менеджером 'with connection:'
            print(f"Помилка цілісності даних (наприклад, дублікат): {e}")
        except sqlite3.Error as e:
            print(f"Сталася помилка бази даних під час заповнення: {e}")


if __name__ == "__main__":
    seed_database()
