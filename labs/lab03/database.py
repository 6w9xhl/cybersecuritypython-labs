#єдине місце, де відкривається з'єднання з базою, і функція створення таблиць зі schema.sql.
#python -m labs.lab03.database.


import sqlite3
from contextlib import closing
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "data" / "lab3.sqlite3"
SCHEMA_PATH = BASE_DIR / "schema.sql"


def get_connection() -> sqlite3.Connection:
    """Відкрити з'єднання з перевіркою зовнішніх ключів."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    try:
        # вмикати для КОЖНОГО з'єднання, інакше SQLite їх ігнорує
        connection.execute("PRAGMA foreign_keys = ON")
        return connection
    except sqlite3.Error:
        connection.close()
        raise



def initialize_database() -> None:
    """створює таблиці зі schema.sql."""
    script = SCHEMA_PATH.read_text(encoding="utf-8")
    with closing(get_connection()) as connection:
        try:
            connection.executescript(script)
        except sqlite3.Error:
            connection.rollback()
            raise


if __name__ == "__main__":
    initialize_database()
