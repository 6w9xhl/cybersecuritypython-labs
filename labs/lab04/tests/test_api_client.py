# noqa: D203
"""НАВІЩО ЦЕЙ ФАЙЛ: тести для «кур'єра» api_client.py.

Справжній сайт NVD тут не використовується. Замість функції requests.get, яка ходить
в інтернет, ми підставляємо «манекен» (Mock). Кур'єр думає, що відправив запит,
а ми потім питаємо манекена: «з якими параметрами тебе викликали?».

Так перевіряється справжній код кур'єра: адреса, cveId, заголовки, таймаут,
а також що він робить, коли сайт відповів помилкою чи не відповів зовсім.
"""

from typing import Any
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client

CVE = "CVE-2099-10001"
URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# Манекен «відповіді сайту»: каже статус, який ми задали, і віддає наші дані як JSON
# Важливо: raise_for_status() у манекена сам НІЧОГО не робить, навіть при статусі 500.
# Щоб він підняв помилку, треба окремо сказати йому це через side_effect
def fake_response(status_code: int = 200, payload: Any = None) -> Mock:
    """Створює двійник requests.Response з успішним raise_for_status()."""
    response = Mock(spec=requests.Response)
    response.status_code = status_code
    response.headers = {"Content-Type": "application/json; charset=utf-8"}
    response.json.return_value = payload
    return response


# Підміняє requests.get саме там, де його шукає кур'єр (api_client.requests.get)
# monkeypatch після тесту сам поверне справжню функцію назад
def install_get(monkeypatch: pytest.MonkeyPatch, **mock_kwargs: Any) -> Mock:
    """Підміняє requests.get у модулі клієнта і повертає двійник."""
    fake_get = Mock(**mock_kwargs)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    return fake_get


# build_headers
# Перевіряємо заголовки до запиту. Ключ тут завжди вигаданий, не справжній


def test_headers_without_key() -> None:
    """Без змінної NVD_API_KEY — лише Accept."""
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_headers_with_fake_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Вигаданий ключ передається в заголовку apiKey без крайніх пробілів."""
    monkeypatch.setenv("NVD_API_KEY", "  fake-test-key-123  ")
    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": "fake-test-key-123",
    }


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_headers_blank_key_ignored(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    """Порожнє або пробільне значення означає запуск без ключа."""
    monkeypatch.setenv("NVD_API_KEY", value)
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_key_read_at_call_time(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ключ читається під час виклику, а не під час імпорту модуля."""
    assert "apiKey" not in api_client.build_headers()
    monkeypatch.setenv("NVD_API_KEY", "later-key")
    assert api_client.build_headers()["apiKey"] == "later-key"


#  fetch_response
# Перевіряємо сам запит і реакцію на помилки сайту. requests.get — завжди манекен


def test_fetch_uses_expected_request(monkeypatch: pytest.MonkeyPatch) -> None:
    """Успішний запит: адреса, cveId у params, заголовки, таймаут, без перенаправлень."""
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = fake_response(payload=payload)
    fake_get = install_get(monkeypatch, return_value=response)

    assert api_client.fetch_response(CVE) == payload
    fake_get.assert_called_once_with(
        URL,
        params={"cveId": CVE},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_sends_key_in_header_not_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ключ передається в заголовку apiKey і не потрапляє в URL чи params."""
    monkeypatch.setenv("NVD_API_KEY", "fake-test-key")
    fake_get = install_get(monkeypatch, return_value=fake_response(payload={}))

    api_client.fetch_response(CVE)
    args, kwargs = fake_get.call_args
    assert args == (URL,)
    assert kwargs["headers"] == {"Accept": "application/json", "apiKey": "fake-test-key"}
    assert kwargs["params"] == {"cveId": CVE}


@pytest.mark.parametrize("status", [404, 403, 500, 503])
def test_fetch_http_error(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    """HTTP-помилка з raise_for_status() пробрасується, JSON не декодується."""
    response = fake_response(status_code=status)
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        f"{status} error", response=response
    )
    install_get(monkeypatch, return_value=response)

    with pytest.raises(requests.exceptions.HTTPError) as exc_info:
        api_client.fetch_response(CVE)
    assert exc_info.value.response.status_code == status
    response.json.assert_not_called()


@pytest.mark.parametrize("status", [204, 301, 302])
def test_fetch_unexpected_status(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    """Статус без HTTP-помилки, але не 200 (зокрема перенаправлення), відхиляється."""
    response = fake_response(status_code=status)
    install_get(monkeypatch, return_value=response)

    with pytest.raises(api_client.UnexpectedStatusError) as exc_info:
        api_client.fetch_response(CVE)
    assert exc_info.value.status_code == status
    response.json.assert_not_called()


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ConnectionError("connection refused"),
        requests.exceptions.ConnectTimeout("connect timeout"),
        requests.exceptions.ReadTimeout("read timeout"),
    ],
)
def test_fetch_network_errors(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    """Мережеві винятки та таймаути пробрасуються викликачу."""
    install_get(monkeypatch, side_effect=error)
    with pytest.raises(type(error)):
        api_client.fetch_response(CVE)


def test_fetch_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    """Неправильне тіло відповіді → requests.exceptions.JSONDecodeError."""
    response = fake_response()
    response.json.side_effect = requests.exceptions.JSONDecodeError("Invalid JSON", "{", 1)
    install_get(monkeypatch, return_value=response)

    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response(CVE)


def test_real_network_is_blocked() -> None:
    """Автоматична фікстура забороняє справжні запити Requests."""
    with pytest.raises(AttributeError):
        requests.get(URL, timeout=1)
