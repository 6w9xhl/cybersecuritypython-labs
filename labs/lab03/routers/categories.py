# маршрути /categories
# Маршрути «тонкі»: запит - repository -
# винятки перетворюються на HTTP-коди [404] [409]

from typing import Any

from fastapi import APIRouter, HTTPException, Path, Response, status

from labs.lab03 import repository
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter(
    prefix="/categories",
    tags=["Категорії"],
)


# GET /categories - 200, список категорій за зростанням id
@router.get(
    "",
    response_model=list[CategoryRead],
    summary="Отримати список категорій",
    description="Повертає всі категорії, відсортовані за зростанням id.",
)
def read_categories() -> list[dict[str, Any]]:
    """Отримати список усіх категорій."""
    return repository.get_categories()


# POST /categories - 201; [409] якщо така назва вже існує
@router.post(
    "",
    response_model=CategoryRead,
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {"description": "Категорія з такою назвою вже існує."},
    },
    summary="Створити категорію",
    description="Створює нову категорію з унікальною назвою.",
)
def create_category(payload: CategoryCreate) -> dict[str, Any]:
    """Створити нову категорію."""
    try:
        return repository.create_category(payload.name)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


# DELETE /categories/{category_id} - 204 без тіла
@router.delete(
    "/{category_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    responses={
        404: {"description": "Категорію не знайдено."},
        409: {"description": "Категорія містить записи."},
    },
    summary="Видалити категорію",
    description="Видаляє категорію, якщо вона не містить записів.",
)
def remove_category(
    category_id: int = Path(
        gt=0,
        description="Додатний ідентифікатор категорії.",
    ),
) -> Response:
    """Видалити категорію за її ID."""
    try:
        deleted = repository.delete_category(category_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Категорію не знайдено.",
        )

    return Response(status_code=status.HTTP_204_NO_CONTENT)
