"""Маршрути для роботи з записами (знахідками вразливостей)."""

from typing import Any

from fastapi import APIRouter, HTTPException, Path, Query, Response, status

from labs.lab03 import repository
from labs.lab03.schemas import RecordCreate, RecordRead, RecordReplace

router = APIRouter(
    prefix="/records",
    tags=["Записи"],
)


@router.get(
    "",
    response_model=list[RecordRead],
    summary="Отримати список записів",
    description=(
        "Повертає записи із фільтрацією за категорією, статусом, "
        "мінімальною оцінкою та пошуком у назві. "
        "Підтримує пагінацію (limit, offset). Сортування за id."
    ),
)
def read_records(
    category_id: int | None = Query(
        default=None,
        gt=0,
        description="Фільтр за ідентифікатором категорії.",
    ),
    status: str | None = Query(
        default=None,
        description="Фільтр за статусом (new, in_progress, done).",
    ),
    min_value: float | None = Query(
        default=None,
        ge=0,
        le=10,
        description="Фільтр: значення value не менше заданого.",
    ),
    q: str | None = Query(
        default=None,
        min_length=1,
        max_length=120,
        description="Пошук підрядка у назві (title).",
    ),
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
        description="Максимальна кількість записів у відповіді.",
    ),
    offset: int = Query(
        default=0,
        ge=0,
        description="Зсув для пагінації.",
    ),
) -> list[dict[str, Any]]:
    """Повертає список записів із застосованими фільтрами."""
    return repository.get_records(
        category_id=category_id,
        status=status,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    responses={
        404: {"description": "Запис не знайдено."},
    },
    summary="Отримати запис за id",
    description="Повертає повні дані запису разом із назвою категорії.",
)
def read_record(
    record_id: int = Path(
        gt=0,
        description="Додатний ідентифікатор запису.",
    ),
) -> dict[str, Any]:
    """Повертає запис за id або 404."""
    record = repository.get_record_by_id(record_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Запис не знайдено.",
        )
    return record


@router.post(
    "",
    response_model=RecordRead,
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {"description": "Дублікат code або неіснуюча категорія."},
        422: {"description": "Невалідні вхідні дані."},
    },
    summary="Створити запис",
    description="Створює новий запис про знайдену вразливість.",
)
def create_record(payload: RecordCreate) -> dict[str, Any]:
    """Створює запис та повертає його дані з назвою категорії."""
    try:
        return repository.create_record(
            code=payload.code,
            title=payload.title,
            category_id=payload.category_id,
            value=payload.value,
            status=payload.status,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    responses={
        404: {"description": "Запис не знайдено."},
        409: {"description": "Дублікат code або неіснуюча категорія."},
        422: {"description": "Невалідні вхідні дані."},
    },
    summary="Повністю оновити запис",
    description="Замінює всі змінювані поля запису (PUT семантика).",
)
def replace_record(
    record_id: int = Path(
        gt=0,
        description="Додатний ідентифікатор запису.",
    ),
    payload: RecordReplace = ...,
) -> dict[str, Any]:
    """Повністю оновлює запис за id."""
    try:
        updated = repository.update_record(
            record_id=record_id,
            code=payload.code,
            title=payload.title,
            category_id=payload.category_id,
            value=payload.value,
            status=payload.status,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Запис не знайдено.",
        )

    return updated


@router.delete(
    "/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    responses={
        404: {"description": "Запис не знайдено."},
    },
    summary="Видалити запис",
    description="Видаляє запис за id.",
)
def remove_record(
    record_id: int = Path(
        gt=0,
        description="Додатний ідентифікатор запису.",
    ),
) -> Response:
    """Видаляє запис."""
    deleted = repository.delete_record(record_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Запис не знайдено.",
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {"description": "Дублікат code у пакеті або в БД — жоден запис не додано."},
        422: {"description": "Невалідні вхідні дані."},
    },
    summary="Пакетне створення записів",
    description=(
        "Додає кілька записів у межах однієї транзакції. "
        "Якщо хоча б один запис порушує обмеження — "
        "транзакція скасовується, жоден запис не зберігається."
    ),
)
def create_records_bulk(payload: list[RecordCreate]) -> list[dict[str, Any]]:
    """Пакетно створює записи в одній транзакції."""
    # Конвертуємо Pydantic-моделі в словники для репозиторію
    records_data = [item.model_dump() for item in payload]
    try:
        return repository.create_records_bulk(records_data)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except RuntimeError as exc:
        # Наприклад, не вдалося прочитати створений запис
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc
