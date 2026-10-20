import sqlite3
from contextlib import closing
from typing import Any

from labs.lab03.database import get_connection

# --- РОБОТА З КАТЕГОРІЯМИ ---


def get_categories() -> list[dict[str, Any]]:
    """Повертає список усіх категорій, відсортованих за id."""
    with closing(get_connection()) as connection:
        cursor = connection.execute("SELECT id, name FROM categories ORDER BY id ASC")
        rows = cursor.fetchall()
        return [{"id": row[0], "name": row[1]} for row in rows]


def create_category(name: str) -> dict[str, Any]:
    """Створює нову категорію."""
    with closing(get_connection()) as connection:
        try:
            with connection:
                cursor = connection.execute(
                    "INSERT INTO categories (name) VALUES (?)", (name.strip(),)
                )
                category_id = cursor.lastrowid
            return {"id": category_id, "name": name.strip()}
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"Категорія з такою назвою вже існує: {name}") from exc


def delete_category(category_id: int) -> bool:
    """Видаляє порожню категорію. Повертає True, якщо видалено."""
    with closing(get_connection()) as connection:
        with connection:
            # Перевіряємо, чи є записи в цій категорії
            cursor = connection.execute(
                "SELECT COUNT(*) FROM records WHERE category_id = ?", (category_id,)
            )
            count = cursor.fetchone()[0]
            if count > 0:
                raise ValueError("Неможливо видалити категорію, яка містить записи.")

            cursor = connection.execute("DELETE FROM categories WHERE id = ?", (category_id,))
            return cursor.rowcount > 0


# --- РОБОТА З ВРАЗЛИВОСТЯМИ / ЗАПИСАМИ ---


def get_record_by_id(record_id: int) -> dict[str, Any] | None:
    """Отримує один запис за id разом із назвою категорії (JOIN)."""
    with closing(get_connection()) as connection:
        cursor = connection.execute(
            """
            SELECT r.id, r.code, r.title, r.category_id, c.name, r.value, r.status
            FROM records r
            JOIN categories c ON r.category_id = c.id
            WHERE r.id = ?
            """,
            (record_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "id": row[0],
            "code": row[1],
            "title": row[2],
            "category_id": row[3],
            "category_name": row[4],
            "value": row[5],
            "status": row[6],
        }


def get_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Повертає список записів із фільтрами, сортуванням та пагінацією."""
    query = """
        SELECT r.id, r.code, r.title, r.category_id, c.name, r.value, r.status
        FROM records r
        JOIN categories c ON r.category_id = c.id
        WHERE 1=1
    """
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
        # Буквальний пошук підрядка згідно з методичкою (instr > 0)
        query += " AND instr(r.title, ?) > 0"
        params.append(q)

    query += " ORDER BY r.id ASC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with closing(get_connection()) as connection:
        cursor = connection.execute(query, params)
        rows = cursor.fetchall()
        return [
            {
                "id": row[0],
                "code": row[1],
                "title": row[2],
                "category_id": row[3],
                "category_name": row[4],
                "value": row[5],
                "status": row[6],
            }
            for row in rows
        ]


def create_record(
    code: str,
    title: str,
    category_id: int,
    value: float,
    status: str,
) -> dict[str, Any]:
    """Створює новий запис."""
    with closing(get_connection()) as connection:
        try:
            with connection:
                cursor = connection.execute(
                    """
                    INSERT INTO records (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (code.strip(), title.strip(), category_id, value, status),
                )
                new_id = cursor.lastrowid
            return get_record_by_id(new_id)  # type: ignore
        except sqlite3.IntegrityError as exc:
            msg = "Порушення обмежень (можливо, дублікат code або неіснуюча категорія)"
            raise ValueError(f"{msg}: {exc}") from exc


def update_record(
    record_id: int,
    code: str,
    title: str,
    category_id: int,
    value: float,
    status: str,
) -> dict[str, Any] | None:
    """Повністю оновлює змінювані поля запису за id."""
    with closing(get_connection()) as connection:
        try:
            with connection:
                cursor = connection.execute(
                    """
                    UPDATE records
                    SET code = ?, title = ?, category_id = ?, value = ?, status = ?
                    WHERE id = ?
                    """,
                    (code.strip(), title.strip(), category_id, value, status, record_id),
                )
                if cursor.rowcount == 0:
                    return None
            return get_record_by_id(record_id)
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"Порушення обмежень при оновленні: {exc}") from exc


def delete_record(record_id: int) -> bool:
    """Видаляє запис за id. Повертає True, якщо видалено."""
    with closing(get_connection()) as connection:
        with connection:
            cursor = connection.execute("DELETE FROM records WHERE id = ?", (record_id,))
            return cursor.rowcount > 0


def create_records_bulk(
    records_data: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Пакетно додає записи в межах однієї транзакції."""
    select_sql = """
        SELECT r.id, r.code, r.title, r.category_id,
               c.name, r.value, r.status
        FROM records r
        JOIN categories c ON r.category_id = c.id
        WHERE r.id = ?
    """

    with closing(get_connection()) as connection:
        created_ids: list[int] = []

        try:
            with connection:
                for item in records_data:
                    cursor = connection.execute(
                        """
                        INSERT INTO records (
                            code, title, category_id, value, status
                        )
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

                created_records = []

                for record_id in created_ids:
                    row = connection.execute(
                        select_sql,
                        (record_id,),
                    ).fetchone()

                    if row is None:
                        raise RuntimeError("Не вдалося прочитати створений запис.")

                    created_records.append(
                        {
                            "id": row[0],
                            "code": row[1],
                            "title": row[2],
                            "category_id": row[3],
                            "category_name": row[4],
                            "value": row[5],
                            "status": row[6],
                        }
                    )
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"Порушення обмежень (можливо, дублікат code): {exc}") from exc

        return created_records
