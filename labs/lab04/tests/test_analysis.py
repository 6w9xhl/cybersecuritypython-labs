# noqa: D203

"""НАВІЩО ЦЕЙ ФАЙЛ: тести для «експерта» analysis.py.

Ми підсовуємо експерту різні вигадані відповіді NVD і перевіряємо, що висновок
саме такий, як ми чекаємо. Інтернет тут не потрібен зовсім.

Що перевіряється (правило варіанта 1: оцінка >= 7.0 і attackVector == NETWORK)
- оцінка нижче порога, рівно на порозі і вище порога
- висока оцінка, але атака не через мережу
- запис не знайдено, запис відхилено, немає оцінки чи потрібного поля
- Primary-оцінка важливіша за Secondary
- зіпсовані дані (текст замість числа, NaN, null...) дають помилку ValueError
"""

import copy
import math
from typing import Any

import pytest

from labs.lab04 import analysis

CVE = "CVE-2099-10001"
RULE_V1 = {"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"}


# Одна оцінка CVSS. Можна змінити бал, attackVector, тип (Primary/Secondary) і джерело
def metric(
    score: Any = 9.8,
    attack_vector: Any = "NETWORK",
    metric_type: str = "Primary",
    source: str = "nvd@nist.gov",
) -> dict[str, Any]:
    """Створює один елемент cvssMetricV31."""
    return {
        "source": source,
        "type": metric_type,
        "cvssData": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "attackVector": attack_vector,
            "baseScore": score,
        },
    }


# Ціла відповідь NVD з одним записом. Передаємо їй список оцінок із metric()
def payload_with(entries: Any = None, status: Any = "Analyzed", **cve_extra: Any) -> dict:
    """Створює відповідь NVD з одним записом.

    ``entries`` — список cvssMetricV31; None означає, що поле metrics відсутнє.
    ``cve_extra`` додає або замінює поля об'єкта cve.
    """
    cve: dict[str, Any] = {
        "id": CVE,
        "vulnStatus": status,
        "descriptions": [{"lang": "en", "value": "Test description."}],
    }
    if entries is not None:
        cve["metrics"] = {"cvssMetricV31": entries}
    cve.update(cve_extra)
    return {"vulnerabilities": [{"cve": cve}]}


# Проганяє відповідь через обидві функції експерта і повертає готовий звіт
def decide(payload: dict[str, Any], variant: int = 1) -> dict[str, Any]:
    """Проганяє повний ланцюжок extract_record → build_report."""
    return analysis.build_report(analysis.extract_record(payload, CVE), CVE, variant)


# Синтетичний файл
# Перевіряємо, що з nvd_sample.json виходить рівно той звіт, що в методичці


def test_sample_gives_expected_report(sample_payload: dict[str, Any]) -> None:
    """Синтетична відповідь для варіанта 1 дає звіт із прикладу методички."""
    assert decide(sample_payload) == {
        "cve_id": CVE,
        "variant": 1,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": RULE_V1,
        "observed": "NETWORK",
        "decision": "review",
    }


@pytest.mark.parametrize(
    ("variant", "expected"),
    [(v, "review") for v in range(1, 8)] + [(v, "other") for v in range(8, 16)],
)
def test_sample_decision_for_all_variants(
    sample_payload: dict[str, Any], variant: int, expected: str
) -> None:
    """За синтетичним файлом варіанти 1–7 дають review, 8–15 — other."""
    assert decide(sample_payload, variant)["decision"] == expected


def test_extract_does_not_modify_payload(sample_payload: dict[str, Any]) -> None:
    """extract_record і build_report не змінюють отриманий payload."""
    before = copy.deepcopy(sample_payload)
    decide(sample_payload)
    assert sample_payload == before


# Межа порога та ознака
# parametrize = один тест запускається для кожного рядка таблички нижче


@pytest.mark.parametrize(
    ("score", "attack_vector", "expected"),
    [
        (6.9, "NETWORK", "other"),  # нижче порога
        (7.0, "NETWORK", "review"),  # рівно на порозі
        (7, "NETWORK", "review"),  # ціле число на порозі
        (7.1, "NETWORK", "review"),  # вище порога
        (10, "NETWORK", "review"),  # верхня межа шкали
        (0, "NETWORK", "other"),  # нижня межа шкали
        (9.8, "LOCAL", "other"),  # висока оцінка, невідповідна ознака
        (9.8, "ADJACENT_NETWORK", "other"),
        (9.8, "PHYSICAL", "other"),
    ],
)
def test_threshold_and_field(score: float, attack_vector: str, expected: str) -> None:
    """Рішення на межі порога та за невідповідної ознаки."""
    report = decide(payload_with([metric(score=score, attack_vector=attack_vector)]))
    assert report["decision"] == expected
    assert report["observed"] == attack_vector


def test_threshold_change_only_base_score(sample_payload: dict[str, Any]) -> None:
    """Зміна лише baseScore у копії синтетичної відповіді: 6.9 → other, 7.0 → review."""
    data = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]
    data["cvssData"]["baseScore"] = 6.9
    assert decide(sample_payload)["decision"] == "other"
    data["cvssData"]["baseScore"] = 7.0
    assert decide(sample_payload)["decision"] == "review"


# Стани not_found / rejected / insufficient_data
# Ситуації, коли до перевірки правила справа не доходить.


def test_not_found() -> None:
    """Порожній vulnerabilities → not_found, усі поля даних null."""
    record = analysis.extract_record({"totalResults": 0, "vulnerabilities": []}, CVE)
    assert record is None
    assert analysis.build_report(record, CVE, 1) == {
        "cve_id": CVE,
        "variant": 1,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": RULE_V1,
        "observed": None,
        "decision": "not_found",
    }


def test_rejected_ignores_high_score() -> None:
    """Rejected дає rejected навіть за високої оцінки; поля оцінки null."""
    report = decide(payload_with([metric(score=9.8)], status="Rejected"))
    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Test description."
    assert report["score"] is None
    assert report["observed"] is None


def test_rejected_does_not_validate_metrics() -> None:
    """Для Rejected оцінки не аналізуються, тож навіть зіпсовані metrics не є помилкою."""
    payload = payload_with(status="Rejected")
    payload["vulnerabilities"][0]["cve"]["metrics"] = "broken"
    assert decide(payload)["decision"] == "rejected"


def test_missing_status_is_insufficient() -> None:
    """Відсутній vulnStatus → insufficient_data без аналізу оцінок."""
    payload = payload_with([metric()])
    del payload["vulnerabilities"][0]["cve"]["vulnStatus"]
    report = decide(payload)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] is None
    assert report["description"] == "Test description."
    assert report["score"] is None


@pytest.mark.parametrize(
    "cve_extra",
    [
        {},  # metrics відсутній
        {"metrics": {}},  # cvssMetricV31 відсутній
        {"metrics": {"cvssMetricV31": []}},  # порожній список
        {"metrics": {"cvssMetricV40": [metric()]}},  # лише інша версія CVSS
    ],
)
def test_missing_score_is_insufficient(cve_extra: dict[str, Any]) -> None:
    """Відсутня оцінка v3.1 за статусу Analyzed - insufficient_data, не нуль."""
    report = decide(payload_with(**cve_extra))
    assert report["decision"] == "insufficient_data"
    assert report["score"] is None
    assert report["vuln_status"] == "Analyzed"


def test_missing_variant_field_is_insufficient() -> None:
    """Відсутнє поле attackVector → insufficient_data; оцінка у звіті зберігається."""
    entry = metric(score=9.8)
    del entry["cvssData"]["attackVector"]
    report = decide(payload_with([entry]))
    assert report["decision"] == "insufficient_data"
    assert report["score"] == 9.8
    assert report["observed"] is None


def test_missing_field_of_other_variant_is_ignored() -> None:
    """Для варіанта 1 відсутність поля scope (варіант 8) не впливає на рішення."""
    report = decide(payload_with([metric()]), variant=1)
    assert report["decision"] == "review"
    assert decide(payload_with([metric()]), variant=8)["decision"] == "insufficient_data"


# Вибір оцінки
# Коли оцінок кілька: перша Primary перемагає, а без Primary береться перша в списку.


def test_primary_has_priority_over_earlier_secondary() -> None:
    """Перша Primary-оцінка має пріоритет над попередньою Secondary."""
    metrics = [
        metric(score=5.0, attack_vector="LOCAL", metric_type="Secondary", source="other@x"),
        metric(score=9.1, attack_vector="NETWORK", metric_type="Primary", source="nvd@nist.gov"),
        metric(score=1.0, attack_vector="NETWORK", metric_type="Primary", source="late@x"),
    ]
    report = decide(payload_with(metrics))
    assert report["score"] == 9.1
    assert report["score_source"] == "nvd@nist.gov"
    assert report["decision"] == "review"


def test_first_metric_without_primary() -> None:
    """Без Primary вибирається перша оцінка; число і ознака беруться з неї ж."""
    metrics = [
        metric(score=6.5, attack_vector="NETWORK", metric_type="Secondary", source="a@x"),
        metric(score=9.8, attack_vector="NETWORK", metric_type="Secondary", source="b@x"),
    ]
    report = decide(payload_with(metrics))
    assert report["score"] == 6.5
    assert report["score_source"] == "a@x"
    assert report["decision"] == "other"


def test_optional_report_fields_absent() -> None:
    """Відсутні source, version, vectorString записуються як null."""
    entry = metric()
    del entry["source"]
    del entry["cvssData"]["version"]
    del entry["cvssData"]["vectorString"]
    report = decide(payload_with([entry], descriptions=[{"lang": "uk", "value": "Опис"}]))
    assert report["score_source"] is None
    assert report["cvss_version"] is None
    assert report["vector"] is None
    assert report["description"] is None
    assert report["decision"] == "review"


def test_first_non_empty_english_description() -> None:
    """Вибирається перший непорожній англійський опис."""
    descriptions = [
        {"lang": "es", "value": "Descripción"},
        {"lang": "en", "value": "   "},
        {"lang": "en", "value": "Second English."},
    ]
    report = decide(payload_with([metric()], descriptions=descriptions))
    assert report["description"] == "Second English."


# Помилки даних
# Підсовуємо зіпсовані дані. Експерт має не «вдавати, що все добре»,
# а підняти ValueError. pytest.raises(ValueError) = «тут ОЧІКУЄМО помилку»


@pytest.mark.parametrize(
    "bad_value",
    [None, "network", "INTERNET", 1, True, ["NETWORK"]],
)
def test_invalid_variant_field_raises(bad_value: Any) -> None:
    """Значення null або недопустиме значення attackVector — помилка даних."""
    record = analysis.extract_record(payload_with([metric(attack_vector=bad_value)]), CVE)
    with pytest.raises(ValueError):
        analysis.build_report(record, CVE, 1)


@pytest.mark.parametrize(
    "bad_score",
    ["9.8", True, False, None, -0.1, 10.1, math.inf, -math.inf, math.nan, [9.8]],
)
def test_invalid_base_score_raises(bad_score: Any) -> None:
    """Рядок, bool, null, нескінченність, NaN і значення поза 0–10 відхиляються."""
    with pytest.raises(ValueError):
        analysis.extract_record(payload_with([metric(score=bad_score)]), CVE)


def test_missing_base_score_raises() -> None:
    """Вибрана оцінка без baseScore — помилка структури."""
    entry = metric()
    del entry["cvssData"]["baseScore"]
    with pytest.raises(ValueError):
        analysis.extract_record(payload_with([entry]), CVE)


@pytest.mark.parametrize(
    "payload",
    [
        [],  # не словник
        {},  # немає vulnerabilities
        {"vulnerabilities": None},
        {"vulnerabilities": {}},
        {"vulnerabilities": [{"cve": {"id": CVE}}, {"cve": {"id": CVE}}]},  # два записи
        {"vulnerabilities": ["CVE-2099-10001"]},  # елемент не словник
        {"vulnerabilities": [{}]},  # немає cve
        {"vulnerabilities": [{"cve": {"id": "CVE-2099-99999", "vulnStatus": "Analyzed"}}]},
        {"vulnerabilities": [{"cve": {"vulnStatus": "Analyzed"}}]},  # немає id
    ],
)
def test_invalid_structure_raises(payload: Any) -> None:
    """Порушення структури обгортки або запису → ValueError."""
    with pytest.raises(ValueError):
        analysis.extract_record(payload, CVE)


@pytest.mark.parametrize(
    "cve_extra",
    [
        {"vulnStatus": ""},
        {"vulnStatus": None},
        {"vulnStatus": 1},
        {"descriptions": "text"},
        {"descriptions": [{"lang": "en"}]},
        {"descriptions": [{"lang": "en", "value": None}]},
        {"descriptions": ["text"]},
        {"metrics": None},
        {"metrics": []},
        {"metrics": {"cvssMetricV31": None}},
        {"metrics": {"cvssMetricV31": {}}},
        {"metrics": {"cvssMetricV31": ["x"]}},
        {"metrics": {"cvssMetricV31": [{"type": "Primary"}]}},  # немає cvssData
        {"metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": None}]}},
    ],
)
def test_invalid_fields_raise(cve_extra: dict[str, Any]) -> None:
    """Наявні поля з неправильним типом або значенням не замінюються відсутніми."""
    with pytest.raises(ValueError):
        analysis.extract_record(payload_with(**cve_extra), CVE)


@pytest.mark.parametrize(
    ("location", "key", "value"),
    [
        ("metric", "source", ""),
        ("metric", "source", None),
        ("data", "version", "3.0"),
        ("data", "version", 3.1),
        ("data", "vectorString", ""),
        ("data", "vectorString", None),
    ],
)
def test_invalid_optional_report_fields_raise(location: str, key: str, value: Any) -> None:
    """source/version/vectorString, якщо наявні, — непорожні рядки; version = "3.1"."""
    entry = metric()
    (entry if location == "metric" else entry["cvssData"])[key] = value
    with pytest.raises(ValueError):
        analysis.extract_record(payload_with([entry]), CVE)


@pytest.mark.parametrize("variant", [0, 16, True, "1", 1.0])
def test_build_report_rejects_unknown_variant(variant: Any) -> None:
    """build_report приймає лише цілі номери варіантів 1–15."""
    with pytest.raises(ValueError):
        analysis.build_report(None, CVE, variant)
