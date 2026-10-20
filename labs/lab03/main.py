"""FastAPI-додаток: Реєстр вразливостей вебзастосунку (Лабораторна робота №3)."""

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI

from labs.lab03 import database
from labs.lab03.config import APP_DESCRIPTION, APP_TITLE
from labs.lab03.routers import categories, records
from shared.student import get_student_info


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
        "url": "https://github.com/example/cybersecurity-python-labs",
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
)

# Підключаємо маршрутизатори
app.include_router(categories.router)
app.include_router(records.router)


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
