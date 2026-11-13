# noqa: D203
"""НАВІЩО ЦЕЙ ФАЙЛ: тести всієї програми «як з терміналу» (main.py).

Тут ми викликаємо main() так, ніби людина написала команду в терміналі,
і перевіряємо, що програма:
- з файлом (--input) робить звіт і НЕ ходить в інтернет;
- на відсутній чи зламаний файл пише зрозумілу помилку і повертає код 1
- на неправильний --cve чи номер варіанта повертає код 2
- на мережеві помилки повертає код 1 і не показує секретів

Допоміжні інструменти pytest
- tmp_path — тимчасова папка для вигаданих файлів
- capsys — перехоплює, що програма надрукувала (stdout окремо, stderr окремо)
- monkeypatch — тимчасово підміняє функції і номер варіанта
"""

import json
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client, main

CVE = "CVE-2099-10001"
SAMPLE = Path(__file__).resolve().parent.parent / "data" / "nvd_sample.json"


# Створює у тимчасовій папці JSON-файл з тим, що ми передали
def write_json(tmp_path: Path, data: Any, name: str = "response.json") -> Path:
    """Записує дані у тимчасовий UTF-8 JSON-файл."""
    path = tmp_path / name
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return path


# пастка: замість кур'єра ставимо манекен, який валить тест, якщо його покличуть
# Так ми доводимо, що в режимі з файлом програма в інтернет не ходила
def forbid_fetch(monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Підміняє fetch_response двійником, що фіксує будь-яке звернення до мережі."""
    fake = Mock(side_effect=AssertionError("мережевий запит у локальному режимі"))
    monkeypatch.setattr(main.api_client, "fetch_response", fake)
    return fake


# Локальний режим
# Запуск з --input: дані беруться з файла, інтернет не потрібен


def test_local_sample_report(monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    """Локальний запуск із синтетичним файлом друкує один JSON-звіт і не йде в мережу."""
    fake_fetch = forbid_fetch(monkeypatch)

    assert main.main(["--cve", CVE, "--input", str(SAMPLE)]) == 0
    out, err = capsys.readouterr()
    report = json.loads(out)
    assert report["decision"] == "review"
    assert report["score"] == 9.8
    assert report["observed"] == "NETWORK"
    assert report["rule"] == {"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"}
    assert err == ""
    fake_fetch.assert_not_called()


def test_local_output_keeps_unicode(
    tmp_path: Path, sample_payload: dict[str, Any], capsys: Any
) -> None:
    """Звіт виводиться з ensure_ascii=False: кирилиця не екранується."""
    cve = sample_payload["vulnerabilities"][0]["cve"]
    cve["descriptions"][0]["value"] = "Синтетична вразливість"
    path = write_json(tmp_path, sample_payload)

    assert main.main(["--cve", CVE, "--input", str(path)]) == 0
    out = capsys.readouterr().out
    assert "Синтетична вразливість" in out
    assert json.loads(out)["description"] == "Синтетична вразливість"


def test_local_not_found_exit_zero(tmp_path: Path, capsys: Any) -> None:
    """Порожній результат пошуку — звіт not_found і код 0."""
    path = write_json(tmp_path, {"totalResults": 0, "vulnerabilities": []})
    assert main.main(["--cve", CVE, "--input", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "not_found"


def test_local_insufficient_data_exit_zero(
    tmp_path: Path, sample_payload: dict[str, Any], capsys: Any
) -> None:
    """Брак оцінки — звіт insufficient_data і код 0."""
    del sample_payload["vulnerabilities"][0]["cve"]["metrics"]
    path = write_json(tmp_path, sample_payload)
    assert main.main(["--cve", CVE, "--input", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "insufficient_data"


def test_local_missing_file(tmp_path: Path, capsys: Any) -> None:
    """Відсутній файл - код 1, повідомлення у stderr, порожній stdout."""
    assert main.main(["--cve", CVE, "--input", str(tmp_path / "missing.json")]) == 1
    out, err = capsys.readouterr()
    assert out == ""
    assert "не знайдено" in err
    assert "Traceback" not in err


def test_local_invalid_json(tmp_path: Path, capsys: Any) -> None:
    """Некоректний JSON - код 1 і повідомлення у stderr."""
    path = tmp_path / "broken.json"
    path.write_text('{"vulnerabilities": [', encoding="utf-8")
    assert main.main(["--cve", CVE, "--input", str(path)]) == 1
    out, err = capsys.readouterr()
    assert out == ""
    assert "некоректний JSON" in err


def test_local_not_utf8(tmp_path: Path, capsys: Any) -> None:
    """Файл не в UTF-8 - код 1."""
    path = tmp_path / "cp1251.json"
    path.write_bytes('{"опис": 1}'.encode("cp1251"))
    assert main.main(["--cve", CVE, "--input", str(path)]) == 1
    assert "UTF-8" in capsys.readouterr().err


def test_local_directory_instead_of_file(tmp_path: Path, capsys: Any) -> None:
    """Каталог замість файла — помилка читання, код 1."""
    assert main.main(["--cve", CVE, "--input", str(tmp_path)]) == 1
    assert capsys.readouterr().err.startswith("Помилка:")


def test_local_invalid_structure(
    tmp_path: Path, sample_payload: dict[str, Any], capsys: Any
) -> None:
    """Порушення структури даних (рядок замість числа) → код 1."""
    entry = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]
    entry["cvssData"]["baseScore"] = "9.8"
    path = write_json(tmp_path, sample_payload)
    assert main.main(["--cve", CVE, "--input", str(path)]) == 1
    out, err = capsys.readouterr()
    assert out == ""
    assert "baseScore" in err


def test_local_cve_mismatch(capsys: Any) -> None:
    """Ідентифікатор --cve перевіряється за відповіддю навіть у локальному режимі."""
    assert main.main(["--cve", "CVE-2099-10002", "--input", str(SAMPLE)]) == 1
    assert "cve.id" in capsys.readouterr().err


def test_load_response_reads_file(tmp_path: Path) -> None:
    """load_response повертає декодований об'єкт."""
    path = write_json(tmp_path, {"vulnerabilities": [], "note": "тест"})
    assert main.load_response(path) == {"vulnerabilities": [], "note": "тест"}


# Аргументи та варіант
# Неправильний запуск. argparse при помилці сам завершує програму (SystemExit з кодом 2),
# тому ловимо це через pytest.raises(SystemExit)


@pytest.mark.parametrize(
    "cve",
    ["cve-2021-44228", "CVE-21-44228", "CVE-2021-442", "CVE-2021-44228 ", "xCVE-2021-44228", ""],
)
def test_invalid_cve_argument(cve: str, capsys: Any) -> None:
    """Неправильний ідентифікатор - SystemExit(2) від argparse."""
    with pytest.raises(SystemExit) as exc_info:
        main.main(["--cve", cve, "--input", str(SAMPLE)])
    assert exc_info.value.code == 2
    assert "CVE" in capsys.readouterr().err


@pytest.mark.parametrize("cve", ["CVE-2021-44228", "CVE-1999-0001", "CVE-2024-1234567"])
def test_valid_cve_formats(cve: str, tmp_path: Path) -> None:
    """Допустимі формати ідентифікатора приймаються."""
    path = write_json(tmp_path, {"vulnerabilities": []})
    assert main.main(["--cve", cve, "--input", str(path)]) == 0


def test_missing_cve_argument() -> None:
    """Без обов'язкового --cve - SystemExit(2)."""
    with pytest.raises(SystemExit) as exc_info:
        main.main(["--input", str(SAMPLE)])
    assert exc_info.value.code == 2


@pytest.mark.parametrize("variant", [0, 16, -1, True, "1", 1.0, None])
def test_invalid_variant_number(monkeypatch: pytest.MonkeyPatch, variant: Any, capsys: Any) -> None:
    """Номер варіанта поза 1–15, bool або не int →-код 2."""
    monkeypatch.setattr(main, "VARIANT_NUMBER", variant)
    assert main.main(["--cve", CVE, "--input", str(SAMPLE)]) == 2
    out, err = capsys.readouterr()
    assert out == ""
    assert "варіанта" in err


def test_other_variant_via_monkeypatch(monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    """Варіант 8 за синтетичним файлом дає other."""
    monkeypatch.setattr(main, "VARIANT_NUMBER", 8)
    assert main.main(["--cve", CVE, "--input", str(SAMPLE)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["variant"] == 8
    assert report["decision"] == "other"


#  Мережевий режим (підміна fetch_response)
# Запуск без --input. Замість справжнього кур'єра — манекен, який повертає дані
# або підкидає потрібну помилку. Перевіряємо, як main.py на це реагує


def test_network_mode_uses_fetch(
    monkeypatch: pytest.MonkeyPatch, sample_payload: dict[str, Any], capsys: Any
) -> None:
    """Без --input дані отримуються через api_client.fetch_response(cve)."""
    fake_fetch = Mock(return_value=sample_payload)
    monkeypatch.setattr(main.api_client, "fetch_response", fake_fetch)

    assert main.main(["--cve", CVE]) == 0
    fake_fetch.assert_called_once_with(CVE)
    assert json.loads(capsys.readouterr().out)["decision"] == "review"


# Створює HTTP-помилку із заданим кодом. Слово "secret" у тексті — навмисне:
# тест перевіряє, що цей текст НЕ потрапить у повідомлення для людини
def _http_error(status: int) -> requests.exceptions.HTTPError:
    """Створює HTTPError із відповіддю заданого статусу."""
    response = Mock(spec=requests.Response)
    response.status_code = status
    return requests.exceptions.HTTPError("secret body text", response=response)


@pytest.mark.parametrize(
    ("error", "expected_text"),
    [
        (requests.exceptions.ConnectTimeout("secret details"), "час очікування"),
        (requests.exceptions.ReadTimeout("secret details"), "час очікування"),
        (requests.exceptions.ConnectionError("secret details"), "з'єднатися"),
        (_http_error(404), "статус 404"),
        (_http_error(503), "статус 503"),
        (api_client.UnexpectedStatusError(301), "статус 301"),
        (requests.exceptions.JSONDecodeError("secret details", "{", 1), "JSON"),
        (requests.exceptions.TooManyRedirects("secret details"), "TooManyRedirects"),
    ],
)
def test_network_errors_exit_one(
    monkeypatch: pytest.MonkeyPatch, error: Exception, expected_text: str, capsys: Any
) -> None:
    """Мережеві/HTTP-помилки - код 1, власне повідомлення без тексту винятку."""
    monkeypatch.setattr(main.api_client, "fetch_response", Mock(side_effect=error))

    assert main.main(["--cve", CVE]) == 1
    out, err = capsys.readouterr()
    assert out == ""
    assert expected_text in err
    assert "secret" not in err
    assert "Traceback" not in err


def test_network_http_error_does_not_leak_key(monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    """Повний ланцюжок із підміною requests.get: ключ не з'являється у виводі."""
    monkeypatch.setenv("NVD_API_KEY", "fake-secret-key")
    response = Mock(spec=requests.Response)
    response.status_code = 403
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "403 Forbidden for apiKey=fake-secret-key", response=response
    )
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    assert main.main(["--cve", CVE]) == 1
    out, err = capsys.readouterr()
    assert "статус 403" in err
    assert "fake-secret-key" not in out + err
    assert fake_get.call_args.kwargs["headers"]["apiKey"] == "fake-secret-key"
