# noqa: D203
"""НАВІЩО ЦЕЙ ФАЙЛ: «адміністратор», точка запуску всієї програми.

Що він робить:
1. Читає, що написано в терміналі (--cve і --input)
2. Вирішує, звідки брати дані: з файла (якщо є --input) чи з сайту NVD.
3. Віддає дані «експерту» analysis.py і отримує від нього звіт.
4. Друкує звіт або зрозуміле повідомлення про помилку.
5. Повертає код завершення: 0 — все добре, 1 — проблема з даними, 2 — неправильний запуск.

Приклади запуску::

    python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
    python -m labs.lab04.main --cve CVE-2021-44228
"""

import argparse
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import requests

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER

# Шаблон номера: «CVE-», 4 цифри року, «-», 4 або більше цифр. Великі літери обов'язкові
CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
MIN_VARIANT, MAX_VARIANT = 1, 15

EXIT_OK = 0  # звіт сформовано
EXIT_DATA_ERROR = 1  # не вдалося отримати, прочитати чи перевірити дані
EXIT_USAGE_ERROR = 2  # програму запустили неправильно


def load_response(path: str | Path) -> Any:
    """Читає UTF-8 JSON-файл із відповіддю NVD і повертає декодований об'єкт.

    Винятки:
        OSError: файл не вдалося відкрити або прочитати.
        UnicodeDecodeError: файл не є коректним UTF-8.
        json.JSONDecodeError: вміст не є коректним JSON.

    """
    # Читаємо весь файл як текст (кодування UTF-8)
    text = Path(path).read_text(encoding="utf-8")
    # Перетворюємо JSON-текст на словник Python.
    return json.loads(text)


def _cve_id(value: str) -> str:
    """Тип аргументу argparse: повний збіг з CVE-YYYY-NNNN (з урахуванням регістру)."""
    # fullmatch — весь рядок має підходити під шаблон, без зайвих символів.
    if not CVE_PATTERN.fullmatch(value):
        # argparse сам надрукує цей текст і завершить програму з кодом 2.
        raise argparse.ArgumentTypeError(
            f"неправильний ідентифікатор {value!r}, очікується формат CVE-РРРР-NNNN"
        )
    return value


def _build_parser() -> argparse.ArgumentParser:
    """Створює парсер аргументів командного рядка."""
    # Описуємо, які аргументи програма приймає.
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab04.main",
        description="Звіт про вразливість з NVD CVE API 2.0 за правилом варіанта.",
    )
    # --cve обов'язковий, і перед використанням перевіряється функцією _cve_id.
    parser.add_argument("--cve", required=True, type=_cve_id, help="ідентифікатор CVE")
    # --input необов'язковий: якщо його немає, підемо в інтернет.
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="шлях до локальної відповіді NVD (JSON, UTF-8); без мережевих запитів",
    )
    return parser


def _is_valid_variant(value: Any) -> bool:
    """Перевіряє, що номер варіанта — ціле число 1–15, яке не є bool."""
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and MIN_VARIANT <= value <= MAX_VARIANT
    )


def _error(message: str) -> None:
    """Виводить повідомлення про помилку у stderr."""
    # Помилки йдуть в окремий «канал» stderr, щоб не змішуватись зі звітом.
    print(f"Помилка: {message}", file=sys.stderr)


def _read_local(path: Path) -> tuple[Any, bool]:
    """Читає локальну відповідь; повертає (payload, успіх)."""
    # Пробуємо прочитати файл. Кожну можливу проблему ловимо окремо
    # і пишемо людині зрозуміле пояснення замість страшного Traceback
    try:
        return load_response(path), True
    except UnicodeDecodeError:
        _error(f"файл {path} не є коректним UTF-8")
    except json.JSONDecodeError as exc:
        _error(f"файл {path} містить некоректний JSON (рядок {exc.lineno}, стовпець {exc.colno})")
    except FileNotFoundError:
        _error(f"файл {path} не знайдено")
    except OSError as exc:
        # Будь-яка інша проблема з файлом (наприклад, вказали папку замість файла)
        _error(f"не вдалося прочитати файл {path} ({type(exc).__name__})")
    return None, False


def _read_remote(cve_id: str) -> tuple[Any, bool]:
    """Отримує відповідь з NVD API; повертає (payload, успіх).

    Не виводить ключ, заголовки, текст мережевого винятку чи тіло відповіді.
    """
    # Просимо «кур'єра» сходити в NVD. Якщо щось пішло не так — пояснюємо людині що.
    # Текст самої помилки не друкуємо: там випадково може опинитися секрет.
    try:
        return api_client.fetch_response(cve_id), True
    except requests.exceptions.Timeout:
        _error("перевищено час очікування відповіді NVD API")
    except requests.exceptions.ConnectionError:
        _error("не вдалося з'єднатися з NVD API")
    except requests.exceptions.HTTPError as exc:
        # Показуємо тільки код статусу (404, 503...), без тіла відповіді.
        status = exc.response.status_code if exc.response is not None else "невідомий"
        _error(f"NVD API повернув HTTP-помилку, статус {status}")
    except api_client.UnexpectedStatusError as exc:
        _error(f"NVD API повернув неочікуваний статус {exc.status_code}")
    except requests.exceptions.JSONDecodeError:
        _error("відповідь NVD API не є коректним JSON")
    except requests.exceptions.RequestException as exc:
        # Інші мережеві проблеми бібліотеки requests — показуємо лише назву помилки.
        _error(f"помилка запиту до NVD API ({type(exc).__name__})")
    return None, False


def main(argv: Sequence[str] | None = None) -> int:
    """Запускає утиліту і повертає код завершення.

    Неправильні аргументи обробляє argparse: повідомлення у stderr і код 2.
    """
    if not _is_valid_variant(VARIANT_NUMBER):
        _error(f"номер варіанта має бути цілим числом від {MIN_VARIANT} до {MAX_VARIANT}")
        return EXIT_USAGE_ERROR

    # Читаємо аргументи з терміналу (неправильні — argparse сам завершить з кодом 2)
    args = _build_parser().parse_args(argv)

    # Беремо дані: з файла, якщо вказано --input, інакше - з інтернету
    if args.input is not None:
        payload, ok = _read_local(args.input)
    else:
        payload, ok = _read_remote(args.cve)
    if not ok:
        return EXIT_DATA_ERROR

    # Віддаємо дані «експерту»: він перевіряє їх і пише звіт.
    # Якщо дані зіпсовані, експерт піднімає ValueError — тоді код 1.
    try:
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, VARIANT_NUMBER)
    except ValueError as exc:
        _error(f"некоректні дані відповіді: {exc}")
        return EXIT_DATA_ERROR

    # stdout — для результату (JSON-звіту), stderr — для повідомлень про помилки.
    # Їх розділяють, щоб при перенаправленні > report.json у файл потрапив лише чистий JSON,
    # а помилки не зіпсували результат. ensure_ascii=False друкує кирилицю літерами,
    # а не escape-кодами \uXXXX.
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
