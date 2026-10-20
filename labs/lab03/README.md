# Лабораторна робота №3: Web API на FastAPI та SQLite

**Варіант 1** — Реєстр вразливостей вебзастосунку

## Опис

Web API для обліку знахідок перевірки вебзастосунку.
Поле `value` містить навчальну оцінку небезпеки вразливості за шкалою від 0 до 10.
Порогове значення становить 7.0.

## Стек технологій

- **Python** 3.10+
- **FastAPI** — веб-фреймворк
- **SQLite** — вбудована БД (файл `data/lab3.sqlite3`)
- **Pydantic v2** — валідація даних
- **Ruff** — лінтер та форматер

## Структура проекту

```
labs/lab03/
├── main.py              # FastAPI app, lifespan, routers
├── config.py            # Константи варіанту (threshold, min/max value)
├── database.py          # SQLite connection + PRAGMA foreign_keys
├── schema.sql           # DDL: categories, records (CHECK, FK)
├── repository.py        # SQL-логіка (CRUD + bulk)
├── schemas.py           # Pydantic моделі (Create/Read/Replace)
├── seed.py              # Заповнення БД з data/seed.json
├── data/
│   ├── seed.json        # 3 категорії, 8 записів (variant 1)
│   └── lab3.sqlite3     # Створюється автоматично
└── routers/
    ├── categories.py    # GET/POST/DELETE /categories
    └── records.py       # CRUD + bulk /records
```

## Ендпоінти API

| Метод | Шлях | Опис | Коди відповідей |
|-------|------|------|-----------------|
| GET | `/ping` | Health-check | 200 |
| GET | `/student` | Інформація про студента | 200 |
| GET | `/categories` | Список категорій | 200 |
| POST | `/categories` | Створити категорію | 201, 409 |
| DELETE | `/categories/{id}` | Видалити порожню категорію | 204, 404, 409 |
| GET | `/records` | Список записів (фільтри, пагінація) | 200 |
| GET | `/records/{id}` | Один запис з назвою категорії | 200, 404 |
| POST | `/records` | Створити запис | 201, 409, 422 |
| PUT | `/records/{id}` | Повністю оновити запис | 200, 404, 409, 422 |
| DELETE | `/records/{id}` | Видалити запис | 204, 404 |
| POST | `/records/bulk` | Пакетне створення (транзакція) | 201, 409, 422 |

### Фільтри для `GET /records`

- `category_id` (int > 0) — категорія
- `status` (new/in_progress/done) — статус
- `min_value` (float 0–10) — мінімальна оцінка
- `q` (str) — пошук підрядка в `title` (`instr(title, q) > 0`)
- `limit` (1–100, default 20) — ліміт
- `offset` (int ≥ 0, default 0) — зсув

## Запуск

```bash
# 1. Встановити залежності
pip install -r requirements.txt

# 2. Ініціалізувати БД (створить таблиці)
python -m labs.lab03.database

# 3. Заповнити початковими даними (3 категорії, 8 записів)
python -m labs.lab03.seed

# 4. Запустити сервер
uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
```

Swagger UI: <http://127.0.0.1:8000/docs>

## Перевірка коду (Ruff)

```bash
# Перевірити стиль
ruff check labs/lab03

# Перевірити форматування
ruff format --check labs/lab03

# Авто-виправити
ruff check --fix labs/lab03
ruff format labs/lab03
```

## Приклади запитів (curl)

```bash
# Health-check
curl -i http://127.0.0.1:8000/ping

# Інформація про студента
curl -i http://127.0.0.1:8000/student

# Категорії
curl -i http://127.0.0.1:8000/categories

# Створити категорію
curl -i -X POST http://127.0.0.1:8000/categories \
  -H "Content-Type: application/json" \
  -d '{"name": "api"}'

# Записи з фільтрами
curl -i "http://127.0.0.1:8000/records?category_id=1&status=new&limit=5"

# Створити запис
curl -i -X POST http://127.0.0.1:8000/records \
  -H "Content-Type: application/json" \
  -d '{"code":"V01-09","title":"Test","category_id":1,"value":7.5,"status":"new"}'

# Пакетне створення (атомарно)
curl -i -X POST http://127.0.0.1:8000/records/bulk \
  -H "Content-Type: application/json" \
  -d '[{"code":"V01-10","title":"A","category_id":1,"value":5.0,"status":"new"},
       {"code":"V01-11","title":"B","category_id":2,"value":8.0,"status":"done"}]'
```

## Валідація даних

- **Category.name**: 2–40 символів, унікальний
- **Record.code**: 3–40 символів, унікальний
- **Record.title**: 3–120 символів
- **Record.value**: float 0.0–10.0 (NaN/Inf заборонено)
- **Record.status**: `new` | `in_progress` | `done`
- **Foreign key**: `records.category_id → categories.id` (ON DELETE RESTRICT)

## Автор

Кучма Христина Юріївна, група КБ-201, варіант 1