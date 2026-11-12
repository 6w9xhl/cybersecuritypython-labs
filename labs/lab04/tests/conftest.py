"""Спільні фікстури тестів ЛР №4: ізоляція від мережі та синтетичні відповіді."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

SAMPLE_PATH = Path(__file__).resolve().parent.parent / "data" / "nvd_sample.json"
SAMPLE_CVE = "CVE-2099-10001"


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Забороняє справжні запити Requests і прибирає успадкований ключ API."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")


@pytest.fixture(scope="session")
def _sample_payload_source() -> dict[str, Any]:
    """Один раз читає синтетичну відповідь NVD із файла."""
    return json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def sample_payload(_sample_payload_source: dict[str, Any]) -> dict[str, Any]:
    """Глибока копія синтетичної відповіді для кожного тесту."""
    return copy.deepcopy(_sample_payload_source)
