"""Клієнт NVD CVE API 2.0: заголовки запиту та один GET-запит.

Модуль не друкує повідомлень і не перевіряє змісту відповіді:
семантичну перевірку виконує ``labs.lab04.analysis``.
"""

import os
from typing import Any

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# (час встановлення з'єднання, час очікування даних під час читання), секунди
REQUEST_TIMEOUT = (3.05, 10)
API_KEY_ENV = "NVD_API_KEY"


class UnexpectedStatusError(Exception):
    """Сервер повернув статус, відмінний від 200, без HTTP-помилки (наприклад, 3xx)."""

    def __init__(self, status_code: int) -> None:
        super().__init__(f"Неочікуваний HTTP-статус: {status_code}")
        self.status_code = status_code


def build_headers() -> dict[str, str]:
    """Повертає заголовки запиту до NVD.

    Завжди містить ``Accept: application/json``. Якщо змінна середовища
    ``NVD_API_KEY`` має непорожнє (після обрізання пробілів) значення,
    додає його в заголовок ``apiKey``. Змінна читається під час виклику.
    """
    headers = {"Accept": "application/json"}
    api_key = (os.getenv(API_KEY_ENV) or "").strip()
    if api_key:
        headers["apiKey"] = api_key
    return headers


def fetch_response(cve_id: str) -> Any:
    """Виконує один GET-запит до NVD за ідентифікатором CVE і повертає декодований JSON.

    Винятки:
        requests.exceptions.Timeout: перевищено таймаут з'єднання або читання.
        requests.exceptions.ConnectionError: не вдалося з'єднатися із сервером.
        requests.exceptions.HTTPError: сервер повернув статус 4xx або 5xx.
        UnexpectedStatusError: статус не 4xx/5xx, але й не 200 (зокрема перенаправлення).
        requests.exceptions.JSONDecodeError: тіло відповіді не є коректним JSON.

    """
    response = requests.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        headers=build_headers(),
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code != 200:
        raise UnexpectedStatusError(response.status_code)
    return response.json()
