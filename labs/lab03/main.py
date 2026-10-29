# ФАЙЛ main.py — ТОЧКА ВХОДУ застосунку FastAPI
# Запуск: uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
# Тут: lifespan, метадані Swagger, підключення роутерів, [500], /ping, /student

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


# lifespan — при старті СТВОРЮЄ відсутні таблиці (дані не стирає й не заповнює)
@asynccontextmanager
async def lifespan(app: FastAPI):
    database.initialize_database()
    yield


# створюємо сам застосунок
app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version="1.0.0",
    lifespan=lifespan,
    contact={
        "name": "Cybersecurity Python Labs",
        "url": "https://github.com/6w9xhl/cybersecuritypython-labs",
    },
)

# Підключаємо маршрутизатори
app.include_router(categories.router)
app.include_router(records.router)


# [500] обробник помилок SQLite: деталі — у журнал, клієнту — загальний текст
@app.exception_handler(sqlite3.Error)
async def sqlite_error_handler(request: Request, exc: sqlite3.Error) -> JSONResponse:
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


# GET /ping — перевірка доступності API - 200 {"status": "ok"}
@app.get(
    "/ping",
    summary="Перевірка доступності API",
    description="Повертає статус ok, якщо сервер запущений.",
    response_model=dict[str, str],
)
def ping() -> dict[str, str]:
    return {"status": "ok"}


# GET /student — ПІБ, група, варіант із shared/student.py - 200
@app.get(
    "/student",
    summary="Інформація про студента",
    description="Повертає прізвище, групу та номер варіанту.",
)
def student() -> dict[str, Any]:
    info = get_student_info()
    return {
        "student_name": info["student_name"],
        "group_name": info["group_name"],
        "variant_number": info["variant_number"],
    }
