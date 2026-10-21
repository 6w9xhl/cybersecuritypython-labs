"""FastAPI-додаток: Реєстр вразливостей вебзастосунку (Лабораторна робота №3)."""

import logging
import sqlite3
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from labs.lab03 import database
from labs.lab03.config import APP_DESCRIPTION, APP_TITLE
from labs.lab03.routers import categories, records
from shared.student import get_student_info

logger = logging.getLogger(__name__)

DATABASE_ERROR_DETAIL = "Внутрішня помилка роботи з базою даних. Спробуйте пізніше."


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Життєвий цикл додатку: ініціалізація БД при старті."""
    # Startup
    database.initialize_database()
    yield
    # Shutdown (якщо потрібно — закриття пулів з'єднань тощо)


app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version="1.0.0",
    lifespan=lifespan,
    contact={
        "name": "Cybersecurity Python Labs",
        "url": "https://github.com/6w9xhl/cybersecuritypython-labs",
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
)

# Підключаємо маршрутизатори
app.include_router(categories.router)
app.include_router(records.router)


@app.exception_handler(sqlite3.Error)
async def sqlite_error_handler(request: Request, exc: sqlite3.Error) -> JSONResponse:
    """Перетворити неочікувану помилку SQLite на зрозумілу відповідь 500.

    Технічні деталі (наприклад, OperationalError через блокування бази) записуються
    в журнал, а клієнт не отримує SQL-команд, файлових шляхів і трасування стека.
    """
    logger.error(
        "Помилка SQLite під час %s %s: %s",
        request.method,
        request.url.path,
        exc,
        exc_info=exc,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": DATABASE_ERROR_DETAIL},
    )


@app.get(
    "/ping",
    summary="Перевірка доступності API",
    description="Повертає статус ok, якщо сервер запущений.",
    response_model=dict[str, str],
)
def ping() -> dict[str, str]:
    """Health-check endpoint."""
    return {"status": "ok"}


@app.get(
    "/student",
    summary="Інформація про студента",
    description="Повертає прізвище, групу та номер варіанту.",
)
def student() -> dict[str, Any]:
    """Інформація про студента з shared/student.py."""
    info = get_student_info()
    return {
        "student_name": info["student_name"],
        "group_name": info["group_name"],
        "variant_number": info["variant_number"],
    }