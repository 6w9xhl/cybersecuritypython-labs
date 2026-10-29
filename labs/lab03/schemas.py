"""Pydantic-моделі запитів і відповідей для Web API."""

# ФАЙЛ schemas.py — Pydantic-моделі запитів і відповідей
# [422] - некоректні дані відхиляються тут
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from labs.lab03.config import VALUE_MAX, VALUE_MIN

RecordStatus = Literal["new", "in_progress", "done"]


# CategoryCreate (тіло запиту) і CategoryRead (відповідь) — категорії
class CategoryCreate(BaseModel):
    """Модель створення категорії."""

    # [422] extra="forbid": зайві поля (зокрема id) заборонені
    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )

    name: str = Field(
        min_length=2,
        max_length=40,
        description="Назва категорії",
        examples=["web"],
    )


# CategoryRead — відповідь для категорії (id + name)
class CategoryRead(BaseModel):
    """Модель відповіді з даними категорії."""

    id: int = Field(gt=0)
    name: str


# RecordCreate — тіло запиту POST /records і POST /records/bulk
# Перевірки: довжини, value 0–10 без NaN/inf, статус, без поля id - [422]
class RecordCreate(BaseModel):
    """Модель створення запису про знайдену вразливість."""

    # обрізання пробілів і заборона зайвих полів
    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )

    code: str = Field(
        min_length=3,
        max_length=40,
        description="Унікальний код знахідки",
        examples=["V01-09"],
    )

    title: str = Field(
        min_length=3,
        max_length=120,
        description="Назва знахідки",
        examples=["Знахідка вебаудиту 09"],
    )

    category_id: int = Field(
        gt=0,
        description="Ідентифікатор категорії",
        examples=[1],
    )

    value: float = Field(
        ge=VALUE_MIN,
        le=VALUE_MAX,
        allow_inf_nan=False,
        description="Навчальна оцінка небезпеки за шкалою 0–10",
        examples=[7.5],
    )

    status: RecordStatus = Field(
        description="Стан опрацювання знахідки",
        examples=["new"],
    )


# RecordReplace — тіло запиту PUT (повна заміна): ті самі поля й правила
class RecordReplace(RecordCreate):
    """Модель повної заміни змінюваних полів запису."""


# RecordRead — відповідь: поля запису + id + category_name
class RecordRead(RecordCreate):
    """Модель відповіді із записом і назвою його категорії."""

    id: int = Field(gt=0)
    category_name: str
