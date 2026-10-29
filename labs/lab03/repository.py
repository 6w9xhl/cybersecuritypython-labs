"""усі SQL-запити. Тут відкриваються з'єднання,
виконуються транзакції та перетворюються помилки SQLite на власні винятки.
Модуль не знає про FastAPI і HTTP.
"""

import logging
import sqlite3
from contextlib import closing
from typing import Any

from labs.lab03.database import get_connection

logger = logging.getLogger(__name__)

# спільний SELECT для читання записів (+ category_name)
RECORD_SELECT = """
    SELECT r.id, r.code, r.title, r.category_id, c.name, r.value, r.status
    FROM records r
    JOIN categories c ON r.category_id = c.id
"""


# Власні винятки (їх перетворюють на HTTP-коди в routers/)
# CategoryNotFoundError - 404;  DuplicateError - 409
class CategoryNotFoundError(Exception):
    """Категорії з вказаним id не існує."""


class DuplicateError(ValueError):
    """Порушено унікальність або інше обмеження даних."""


def _row_to_record(row: tuple[Any, ...]) -> dict[str, Any]:
    """Перетворює рядок вибірки на словник запису."""
    return {
        "id": row[0],
        "code": row[1],
        "title": row[2],
        "category_id": row[3],
        "category_name": row[4],
        "value": row[5],
        "status": row[6],
    }


def _category_exists(connection: sqlite3.Connection, category_id: int) -> bool:
    """Перевіряє існування категорії в межах поточної транзакції."""
    row = connection.execute("SELECT 1 FROM categories WHERE id = ?", (category_id,)).fetchone()
    return row is not None


def _fetch_record(connection: sqlite3.Connection, record_id: int) -> dict[str, Any] | None:
    """Читає один запис із назвою категорії через наявне з'єднання."""
    row = connection.execute(RECORD_SELECT + " WHERE r.id = ?", (record_id,)).fetchone()
    return _row_to_record(row) if row else None


# РОБОТА З КАТЕГОРІЯМИ


def get_categories() -> list[dict[str, Any]]:
    """Повертає список усіх категорій, відсортованих за id."""
    with closing(get_connection()) as connection:
        cursor = connection.execute("SELECT id, name FROM categories ORDER BY id ASC")
        return [{"id": row[0], "name": row[1]} for row in cursor.fetchall()]


# create_category — [409] якщо така назва вже є (UNIQUE - ValueError)
def create_category(name: str) -> dict[str, Any]:
    """Створює нову категорію."""
    clean_name = name.strip()
    with closing(get_connection()) as connection:
        try:
            with connection:
                cursor = connection.execute(
                    "INSERT INTO categories (name) VALUES (?)", (clean_name,)
                )
                category_id = cursor.lastrowid
        except sqlite3.IntegrityError as exc:
            logger.warning("Не вдалося створити категорію: %s", exc)
            raise ValueError("Категорія з такою назвою вже існує.") from exc
    return {"id": category_id, "name": clean_name}


# delete_category — [409] якщо в категорії є записи; [404] якщо її немає (False)
def delete_category(category_id: int) -> bool:
    """Видаляє порожню категорію. Повертає True, якщо видалено."""
    with closing(get_connection()) as connection:
        try:
            with connection:
                count = connection.execute(
                    "SELECT COUNT(*) FROM records WHERE category_id = ?", (category_id,)
                ).fetchone()[0]
                if count > 0:
                    raise ValueError("Неможливо видалити категорію, яка містить записи.")
                cursor = connection.execute("DELETE FROM categories WHERE id = ?", (category_id,))
                return cursor.rowcount > 0
        except sqlite3.IntegrityError as exc:
            # Запис міг з'явитися між перевіркою COUNT і DELETE (ON DELETE RESTRICT).
            logger.warning("Видалення категорії відхилено обмеженням: %s", exc)
            raise ValueError("Неможливо видалити категорію, яка містить записи.") from exc


# РОБОТА ІЗ ЗАПИСАМИ


def get_record_by_id(record_id: int) -> dict[str, Any] | None:
    """Отримує один запис за id разом із назвою категорії (JOIN)."""
    with closing(get_connection()) as connection:
        return _fetch_record(connection, record_id)


# get_records — СПИСОК записів
# Фільтри через AND, сортування за id, [ПАГІНАЦІЯ] limit/offset
# limit це скільки записів повернути максимум,
# offset це скільки записів з початку пропустити
# SQL-ІН'ЄКЦІЯ найкраще видно саме тут: SQL фіксований, значення в params


def get_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Повертає список записів із фільтрами, сортуванням та пагінацією."""
    query = RECORD_SELECT + " WHERE 1=1"
    params: list[Any] = []

    if category_id is not None:
        query += " AND r.category_id = ?"
        params.append(category_id)

    if status is not None:
        query += " AND r.status = ?"
        params.append(status)

    if min_value is not None:
        query += " AND r.value >= ?"
        params.append(min_value)

    if q is not None:
        # Буквальний пошук підрядка з урахуванням регістру (% та _ не є шаблонами)
        query += " AND instr(r.title, ?) > 0"
        params.append(q)

    query += " ORDER BY r.id ASC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with closing(get_connection()) as connection:
        rows = connection.execute(query, params).fetchall()
    return [_row_to_record(row) for row in rows]


# create_record — додає запис
# [404] немає категорії  [409] дубль code
def create_record(
    code: str,
    title: str,
    category_id: int,
    value: float,
    status: str,
) -> dict[str, Any]:
    with closing(get_connection()) as connection:
        try:
            with connection:
                if not _category_exists(connection, category_id):
                    raise CategoryNotFoundError(category_id)
                cursor = connection.execute(
                    """
                    INSERT INTO records (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (code.strip(), title.strip(), category_id, value, status),
                )
                new_id = cursor.lastrowid
                created = _fetch_record(connection, new_id)
        except sqlite3.IntegrityError as exc:
            logger.warning("Порушення обмежень при створенні запису: %s", exc)
            raise DuplicateError("Запис із таким кодом уже існує.") from exc
    if created is None:
        raise RuntimeError("Не вдалося прочитати створений запис.")
    return created


# update_record — повна заміна запису
# None - [404] запису; [404] категорії; [409] дубль code; id не змінюється


def update_record(
    record_id: int,
    code: str,
    title: str,
    category_id: int,
    value: float,
    status: str,
) -> dict[str, Any] | None:
    with closing(get_connection()) as connection:
        try:
            with connection:
                if _fetch_record(connection, record_id) is None:
                    return None
                if not _category_exists(connection, category_id):
                    raise CategoryNotFoundError(category_id)
                connection.execute(
                    """
                    UPDATE records
                    SET code = ?, title = ?, category_id = ?, value = ?, status = ?
                    WHERE id = ?
                    """,
                    (code.strip(), title.strip(), category_id, value, status, record_id),
                )
                return _fetch_record(connection, record_id)
        except sqlite3.IntegrityError as exc:
            logger.warning("Порушення обмежень при оновленні запису: %s", exc)
            raise DuplicateError("Запис із таким кодом уже існує.") from exc


# delete_record — видалення запису; False - [404]
def delete_record(record_id: int) -> bool:
    """Видаляє запис за id. Повертає True, якщо видалено."""
    with closing(get_connection()) as connection:
        with connection:
            cursor = connection.execute("DELETE FROM records WHERE id = ?", (record_id,))
            return cursor.rowcount > 0


def create_records_bulk(records_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    with closing(get_connection()) as connection:
        try:
            with connection:
                for category_id in sorted({item["category_id"] for item in records_data}):
                    if not _category_exists(connection, category_id):
                        raise CategoryNotFoundError(category_id)

                created_ids: list[int] = []
                for item in records_data:
                    cursor = connection.execute(
                        """
                        INSERT INTO records (code, title, category_id, value, status)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            item["code"].strip(),
                            item["title"].strip(),
                            item["category_id"],
                            item["value"],
                            item["status"],
                        ),
                    )
                    created_ids.append(cursor.lastrowid)

                created_records: list[dict[str, Any]] = []
                for record_id in created_ids:
                    record = _fetch_record(connection, record_id)
                    if record is None:
                        raise RuntimeError("Не вдалося прочитати створений запис.")
                    created_records.append(record)
        except sqlite3.IntegrityError as exc:
            logger.warning("Пакет скасовано через порушення обмежень: %s", exc)
            raise DuplicateError("Пакет скасовано: дублікат коду запису.") from exc
    return created_records
