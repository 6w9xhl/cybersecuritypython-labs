"""НАВІЩО ЦЕЙ ФАЙЛ: «кур'єр», який ходить на сайт NVD по дані.

Тут лише дві речі:
- build_headers() готує заголовки до запиту: «хочу JSON» і, якщо є, ключ
- fetch_response() відправляє ОДИН запит у NVD і повертає відповідь як словник Python

Цей файл нічого не друкує і не розбирається, що саме прийшло у відповіді
Перевіркою даних займається analysis.py, а повідомленнями для людини — main.py
"""

import os
from typing import Any

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = (3.05, 10)
API_KEY_ENV = "NVD_API_KEY"


class UnexpectedStatusError(Exception):
    """Сервер повернув статус, відмінний від 200, без HTTP-помилки (наприклад, 3xx)."""

    # Наша власна «тривога» для випадку, коли сайт відповів не 200 і не помилкою,
    # а, наприклад, «йди на іншу адресу» (301/302). Запам'ятовуємо код статусу,
    # щоб main.py міг його показати людині.
    def __init__(self, status_code: int) -> None:
        super().__init__(f"Неочікуваний HTTP-статус: {status_code}")
        self.status_code = status_code


def build_headers() -> dict[str, str]:
    """Повертає заголовки запиту до NVD.

    Завжди містить ``Accept: application/json``. Якщо змінна середовища
    ``NVD_API_KEY`` має непорожнє (після обрізання пробілів) значення,
    додає його в заголовок ``apiKey``. Змінна читається під час виклику.
    """
    # Перший заголовок «відповідай мені у форматі JSON».
    headers = {"Accept": "application/json"}
    # Пробуємо дістати ключ з терміналу. Якщо його немає — буде порожній рядок.
    api_key = (os.getenv(API_KEY_ENV) or "").strip()
    # Ключ кладемо в заголовок (а не в адресу), щоб він не світився в журналах.
    if api_key:
        headers["apiKey"] = api_key
    # Без ключа повертається просто {"Accept": "application/json"} — і це нормально.
    return headers


def fetch_response(cve_id: str) -> Any:
    """Виконує один GET-запит до NVD за ідентифікатором CVE і повертає декодований JSON.

    Винятки:
        requests.exceptions.Timeout: перевищено таймаут з'єднання або читання
        requests.exceptions.ConnectionError: не вдалося з'єднатися із сервером
        requests.exceptions.HTTPError: сервер повернув статус 4xx або 5xx
        UnexpectedStatusError: статус не 4xx/5xx, але й не 200 (зокрема перенаправлення)
        requests.exceptions.JSONDecodeError: тіло відповіді не є коректним JSON

    """
    # Відправляємо запит «дай дані» (GET) на сайт NVD
    response = requests.get(
        NVD_API_URL,  # куди йдемо
        params={"cveId": cve_id},  # що шукаємо: допишеться до адреси як ?cveId=CVE-...
        headers=build_headers(),  # заголовки: «хочу JSON» і ключ, якщо він є
        timeout=REQUEST_TIMEOUT,  # чекати з'єднання 3.05 с, даних - 10 с
        allow_redirects=False,  # не йти на інші адреси
    )
    # Якщо сайт відповів помилкою (404, 500 і т.д.) — тут підніметься тривога HTTPError.
    response.raise_for_status()
    # Помилки немає, але це й не «все добре» (наприклад, перенаправлення 301) — теж тривога.
    if response.status_code != 200:
        raise UnexpectedStatusError(response.status_code)
    return response.json()
