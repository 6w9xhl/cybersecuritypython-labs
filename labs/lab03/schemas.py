"""Pydantic-моделі запитів і відповідей для Web API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from labs.lab03.config import VALUE_MAX, VALUE_MIN

RecordStatus = Literal["new", "in_progress", "done"]


class CategoryCreate(BaseModel):
    """Модель створення категорії."""

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


class CategoryRead(BaseModel):
    """Модель відповіді з даними категорії."""

    id: int = Field(gt=0)
    name: str


class RecordCreate(BaseModel):
    """Модель створення запису про знайдену вразливість."""

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


class RecordReplace(RecordCreate):
    """Модель повної заміни змінюваних полів запису."""


class RecordRead(RecordCreate):
    """Модель відповіді із записом і назвою його категорії."""

    id: int = Field(gt=0)
    category_name: str
