"""НАВІЩО ЦЕЙ ФАЙЛ: спільні «правила і заготовки» для всіх тестів.

pytest знаходить файл з назвою conftest.py сам і підключає його до кожного тесту.
Тут:
- isolated_environment — перед КОЖНИМ тестом вимикає інтернет і прибирає ключ API
- sample_payload — свіжа копія синтетичної відповіді nvd_sample.json для тесту.
"""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

SAMPLE_PATH = Path(__file__).resolve().parent.parent / "data" / "nvd_sample.json"
SAMPLE_CVE = "CVE-2099-10001"


# autouse=True означає «застосовувати до всіх тестів автоматично», навіть якщо тест про це
# не просить. Так неможливо забути вимкнути інтернет у новому тесті
@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Забороняє справжні запити Requests і прибирає успадкований ключ API."""
    # Якщо в терміналі заданий справжній ключ — на час тесту його не буде
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    # «Виламуємо» з requests функцію, яка реально ходить в інтернет
    # Тест, що випадково спробує піти в мережу, одразу впаде з помилкою
    monkeypatch.delattr("requests.sessions.Session.request")


# scope="session" — файл читається лише один раз на весь запуск тестів.
@pytest.fixture(scope="session")
def _sample_payload_source() -> dict[str, Any]:
    """Один раз читає синтетичну відповідь NVD із файла."""
    return json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def sample_payload(_sample_payload_source: dict[str, Any]) -> dict[str, Any]:
    """Глибока копія синтетичної відповіді для кожного тесту."""
    # Кожен тест отримує СВОЮ копію. Якщо тест щось у ній змінить (наприклад, оцінку),
    # це не зачепить інші тести.
    return copy.deepcopy(_sample_payload_source)
