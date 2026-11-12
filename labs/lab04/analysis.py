"""Перевірка відповіді NVD CVE API 2.0 і правило відбору за варіантом.

Функції працюють лише з переданими аргументами: не читають файлів, змінних
середовища чи часу, не виконують HTTP-запитів, нічого не друкують і не змінюють
отриманий ``payload``. Порушення контракту даних спричиняє ``ValueError``.
"""

import math
from typing import Any

# Допустимі значення полів cvssData (CVSS v3.1), що використовуються у варіантах.
ALLOWED_VALUES: dict[str, frozenset[str]] = {
    "attackVector": frozenset({"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"}),
    "attackComplexity": frozenset({"LOW", "HIGH"}),
    "privilegesRequired": frozenset({"NONE", "LOW", "HIGH"}),
    "userInteraction": frozenset({"NONE", "REQUIRED"}),
    "scope": frozenset({"UNCHANGED", "CHANGED"}),
    "confidentialityImpact": frozenset({"NONE", "LOW", "HIGH"}),
    "integrityImpact": frozenset({"NONE", "LOW", "HIGH"}),
    "availabilityImpact": frozenset({"NONE", "LOW", "HIGH"}),
}

# Правила варіантів: score >= threshold і cvssData[field] == expected.
VARIANT_RULES: dict[int, dict[str, Any]] = {
    1: {"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"},
    2: {"threshold": 8.0, "field": "attackComplexity", "expected": "LOW"},
    3: {"threshold": 7.0, "field": "privilegesRequired", "expected": "NONE"},
    4: {"threshold": 8.0, "field": "userInteraction", "expected": "NONE"},
    5: {"threshold": 7.0, "field": "confidentialityImpact", "expected": "HIGH"},
    6: {"threshold": 7.0, "field": "integrityImpact", "expected": "HIGH"},
    7: {"threshold": 7.0, "field": "availabilityImpact", "expected": "HIGH"},
    8: {"threshold": 9.0, "field": "scope", "expected": "CHANGED"},
    9: {"threshold": 5.0, "field": "attackVector", "expected": "LOCAL"},
    10: {"threshold": 6.0, "field": "privilegesRequired", "expected": "LOW"},
    11: {"threshold": 6.0, "field": "userInteraction", "expected": "REQUIRED"},
    12: {"threshold": 6.0, "field": "confidentialityImpact", "expected": "LOW"},
    13: {"threshold": 6.0, "field": "integrityImpact", "expected": "LOW"},
    14: {"threshold": 6.0, "field": "availabilityImpact", "expected": "LOW"},
    15: {"threshold": 8.0, "field": "attackComplexity", "expected": "HIGH"},
}

STATUS_REJECTED = "Rejected"

_MISSING = object()


def _optional_str(container: dict[str, Any], key: str, where: str) -> str | None:
    """Повертає None для відсутнього ключа, інакше вимагає непорожній рядок."""
    value = container.get(key, _MISSING)
    if value is _MISSING:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{where}.{key} має бути непорожнім рядком")
    return value


def _validate_score(value: Any) -> float:
    """Перевіряє, що baseScore — скінченне число (не bool) у межах 0–10."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError("cvssData.baseScore має бути числом")
    if not math.isfinite(value) or not 0 <= value <= 10:
        raise ValueError("cvssData.baseScore має бути скінченним числом від 0 до 10")
    return float(value)


def _pick_description(cve: dict[str, Any]) -> str | None:
    """Повертає перший непорожній англійський опис або None."""
    descriptions = cve.get("descriptions", _MISSING)
    if descriptions is _MISSING:
        return None
    if not isinstance(descriptions, list):
        raise ValueError("cve.descriptions має бути списком")
    chosen = None
    for item in descriptions:
        if not isinstance(item, dict):
            raise ValueError("елементи cve.descriptions мають бути об'єктами")
        lang, value = item.get("lang"), item.get("value")
        if not isinstance(lang, str) or not isinstance(value, str):
            raise ValueError("descriptions[].lang і descriptions[].value мають бути рядками")
        if chosen is None and lang == "en" and value.strip():
            chosen = value
    return chosen


def _extract_cvss(cve: dict[str, Any]) -> dict[str, Any] | None:
    """Вибирає оцінку CVSS v3.1 і перевіряє спільні поля; None — оцінки немає."""
    metrics = cve.get("metrics", _MISSING)
    if metrics is _MISSING:
        return None
    if not isinstance(metrics, dict):
        raise ValueError("cve.metrics має бути об'єктом")
    entries = metrics.get("cvssMetricV31", _MISSING)
    if entries is _MISSING:
        return None
    if not isinstance(entries, list):
        raise ValueError("metrics.cvssMetricV31 має бути списком")
    if not entries:
        return None
    if not all(isinstance(entry, dict) for entry in entries):
        raise ValueError("елементи metrics.cvssMetricV31 мають бути об'єктами")

    selected = next((e for e in entries if e.get("type") == "Primary"), entries[0])

    cvss_data = selected.get("cvssData")
    if not isinstance(cvss_data, dict):
        raise ValueError("cvssMetricV31[].cvssData має бути об'єктом")
    score = _validate_score(cvss_data.get("baseScore"))
    version = _optional_str(cvss_data, "version", "cvssData")
    if version is not None and version != "3.1":
        raise ValueError('cvssData.version має дорівнювати "3.1"')

    return {
        "score": score,
        "source": _optional_str(selected, "source", "cvssMetricV31[]"),
        "version": version,
        "vector": _optional_str(cvss_data, "vectorString", "cvssData"),
        # копія, щоб внутрішній запис не посилався на дані payload
        "data": dict(cvss_data),
    }


def extract_record(payload: Any, cve_id: str) -> dict[str, Any] | None:
    """Перевіряє відповідь NVD і повертає внутрішній запис або None, якщо запис не знайдено.

    Формат внутрішнього запису::

        {
            "cve_id": str,               # cve.id з відповіді (= запитаному)
            "vuln_status": str | None,   # None, якщо vulnStatus відсутній
            "description": str | None,   # перший непорожній англійський опис
            "cvss": None | {             # None — оцінки v3.1 немає або її не аналізують
                "score": float,          # baseScore вибраної оцінки
                "source": str | None,
                "version": str | None,   # "3.1" або None
                "vector": str | None,
                "data": dict,            # копія cvssData вибраної оцінки
            },
        }

    Для статусу ``Rejected`` і відсутнього статусу оцінки не аналізуються (``cvss`` = None).
    Вибирається перша оцінка з ``type="Primary"``, інакше — перша у списку.

    Винятки:
        ValueError: структура, типи або значення полів не відповідають контракту.

    """
    if not isinstance(payload, dict):
        raise ValueError("відповідь має бути JSON-об'єктом")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("поле vulnerabilities має бути списком")
    if not vulnerabilities:
        return None
    if len(vulnerabilities) > 1:
        raise ValueError("для точного ідентифікатора очікується не більше одного запису")

    item = vulnerabilities[0]
    if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
        raise ValueError("елемент vulnerabilities має містити об'єкт cve")
    cve = item["cve"]
    if cve.get("id") != cve_id:
        raise ValueError("cve.id не збігається із запитаним ідентифікатором")

    status = _optional_str(cve, "vulnStatus", "cve")
    description = _pick_description(cve)
    analyze = status is not None and status != STATUS_REJECTED

    return {
        "cve_id": cve_id,
        "vuln_status": status,
        "description": description,
        "cvss": _extract_cvss(cve) if analyze else None,
    }


def build_report(record: dict[str, Any] | None, cve_id: str, variant: int) -> dict[str, Any]:
    """Застосовує правило варіанта до внутрішнього запису і повертає словник звіту.

    Стани ``decision`` перевіряються в порядку: not_found, rejected,
    insufficient_data, review, other.

    Винятки:
        ValueError: невідомий варіант або недопустиме значення поля варіанта.

    """
    if isinstance(variant, bool) or not isinstance(variant, int) or variant not in VARIANT_RULES:
        raise ValueError(f"невідомий номер варіанта: {variant!r}")
    rule = dict(VARIANT_RULES[variant])

    report: dict[str, Any] = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": rule,
        "observed": None,
        "decision": "not_found",
    }
    if record is None:
        return report

    report["description"] = record["description"]
    report["vuln_status"] = record["vuln_status"]

    if record["vuln_status"] == STATUS_REJECTED:
        report["decision"] = "rejected"
        return report

    cvss = record["cvss"]
    if record["vuln_status"] is None or cvss is None:
        report["decision"] = "insufficient_data"
        return report

    report.update(
        cvss_version=cvss["version"],
        score=cvss["score"],
        score_source=cvss["source"],
        vector=cvss["vector"],
    )

    field = rule["field"]
    observed = cvss["data"].get(field, _MISSING)
    if observed is _MISSING:
        report["decision"] = "insufficient_data"
        return report
    if not isinstance(observed, str) or observed not in ALLOWED_VALUES[field]:
        raise ValueError(f"cvssData.{field} має недопустиме значення")

    report["observed"] = observed
    matches = cvss["score"] >= rule["threshold"] and observed == rule["expected"]
    report["decision"] = "review" if matches else "other"
    return report
