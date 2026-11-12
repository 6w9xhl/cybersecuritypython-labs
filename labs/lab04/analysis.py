"""НАВІЩО ЦЕЙ ФАЙЛ: «експерт», який читає відповідь NVD і виносить висновок.

Тут дві головні функції:
- extract_record() перевіряє, що відповідь нормальна, і виписує з неї лише потрібне;
- build_report() застосовує правило варіанта і складає звіт (review / other / ...)

Важливо: експерт тільки «думає». Він не ходить в інтернет, не читає файлів,
нічого не друкує і не змінює дані, які йому дали. Тому його легко тестувати.
Якщо дані зіпсовані, він піднімає ValueError («дані погані»)
"""

import math
from typing import Any

# Які значення взагалі можуть бути в кожному полі CVSS 3.1
# Усе інше (наприклад, "network" малими літерами) — зіпсовані дані.
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

# Правила всіх 15 варіантів. Кожне читається так:
# «оцінка >= threshold І поле field дорівнює expected» -> review.
# Наш варіант 1: оцінка >= 7.0 і attackVector == NETWORK.
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

# Статус «запис відхилено» в NVD — такі записи не аналізуємо
STATUS_REJECTED = "Rejected"
_MISSING = object()


def _optional_str(container: dict[str, Any], key: str, where: str) -> str | None:
    """Повертає None для відсутнього ключа, інакше вимагає непорожній рядок."""
    value = container.get(key, _MISSING)
    # Поля немає - нічого страшного, у звіті буде null
    if value is _MISSING:
        return None
    # Поле є, але це не текст або порожній текст — дані зіпсовані
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{where}.{key} має бути непорожнім рядком")
    return value


def _validate_score(value: Any) -> float:
    """Перевіряє, що baseScore — скінченне число (не bool) у межах 0–10."""
    # True/False у Python рахуються як 1/0, тому відкидаємо їх окремо
    # Рядок "9.8" — теж не число, його не приймаємо
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError("cvssData.baseScore має бути числом")
    # NaN («не число») і нескінченність не підходять, а шкала CVSS — від 0 до 10
    if not math.isfinite(value) or not 0 <= value <= 10:
        raise ValueError("cvssData.baseScore має бути скінченним числом від 0 до 10")
    return float(value)


def _pick_description(cve: dict[str, Any]) -> str | None:
    """Повертає перший непорожній англійський опис або None."""
    descriptions = cve.get("descriptions", _MISSING)
    # Описів немає зовсім — повертаємо None (у звіті буде null)
    if descriptions is _MISSING:
        return None
    # Описи мають бути списком.
    if not isinstance(descriptions, list):
        raise ValueError("cve.descriptions має бути списком")
    chosen = None
    for item in descriptions:
        if not isinstance(item, dict):
            raise ValueError("елементи cve.descriptions мають бути об'єктами")
        lang, value = item.get("lang"), item.get("value")
        if not isinstance(lang, str) or not isinstance(value, str):
            raise ValueError("descriptions[].lang і descriptions[].value мають бути рядками")
        # Запам'ятовуємо перший англійський опис, де є хоч якийсь текст.
        if chosen is None and lang == "en" and value.strip():
            chosen = value
    return chosen


def _extract_cvss(cve: dict[str, Any]) -> dict[str, Any] | None:
    """Вибирає оцінку CVSS v3.1 і перевіряє спільні поля; None — оцінки немає."""
    # Ідемо вглиб відповіді: cve -> metrics -> cvssMetricV31.
    # Якщо на якомусь кроці поля немає — оцінки немає (повертаємо None).
    # Якщо поле є, але неправильного типу — дані зіпсовані (ValueError).
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
    if not entries:  # порожній список — оцінок немає
        return None
    if not all(isinstance(entry, dict) for entry in entries):
        raise ValueError("елементи metrics.cvssMetricV31 мають бути об'єктами")

    selected = next((e for e in entries if e.get("type") == "Primary"), entries[0])

    # Усередині вибраної оцінки шукаємо cvssData — там лежать бал і характеристики.
    cvss_data = selected.get("cvssData")
    if not isinstance(cvss_data, dict):
        raise ValueError("cvssMetricV31[].cvssData має бути об'єктом")
    score = _validate_score(cvss_data.get("baseScore"))  # сам бал 0–10
    version = _optional_str(cvss_data, "version", "cvssData")
    # Нас цікавить лише CVSS версії 3.1
    if version is not None and version != "3.1":
        raise ValueError('cvssData.version має дорівнювати "3.1"')

    # Повертаємо коротку вижимку з вибраної оцінки.
    return {
        "score": score,
        "source": _optional_str(selected, "source", "cvssMetricV31[]"),  # хто оцінював
        "version": version,
        "vector": _optional_str(cvss_data, "vectorString", "cvssData"),  # усе одним рядком
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
    # Відповідь має бути словником, а в ньому — список vulnerabilities.
    if not isinstance(payload, dict):
        raise ValueError("відповідь має бути JSON-об'єктом")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("поле vulnerabilities має бути списком")
    # Порожній список = NVD шукав і нічого не знайшов. Це не помилка.
    if not vulnerabilities:
        return None
    # Ми шукали один конкретний номер, тож більше одного запису — це дивно.
    if len(vulnerabilities) > 1:
        raise ValueError("для точного ідентифікатора очікується не більше одного запису")

    # Беремо єдиний запис і перевіряємо, що це саме та вразливість, яку ми просили.
    item = vulnerabilities[0]
    if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
        raise ValueError("елемент vulnerabilities має містити об'єкт cve")
    cve = item["cve"]
    if cve.get("id") != cve_id:
        raise ValueError("cve.id не збігається із запитаним ідентифікатором")

    status = _optional_str(cve, "vulnStatus", "cve")  # Analyzed, Rejected тощо
    description = _pick_description(cve)
    # Оцінки дивимось, тільки якщо статус є і запис не відхилений.
    analyze = status is not None and status != STATUS_REJECTED

    # вижимка — тільки те, що потрібно для звіту.
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
    # Беремо правило свого варіанта
    if isinstance(variant, bool) or not isinstance(variant, int) or variant not in VARIANT_RULES:
        raise ValueError(f"невідомий номер варіанта: {variant!r}")
    rule = dict(VARIANT_RULES[variant])

    # Заготовка звіту: усі 11 ключів є завжди, спочатку майже всі порожні (null)
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
    # Далі йдемо зверху вниз і зупиняємось на першому стані, що підійшов.

    #  Запис не знайдено -> not_found
    if record is None:
        return report

    report["description"] = record["description"]
    report["vuln_status"] = record["vuln_status"]

    # Запис відхилений -> rejected, оцінки не дивимось
    if record["vuln_status"] == STATUS_REJECTED:
        report["decision"] = "rejected"
        return report

    # Немає статусу або немає оцінки -> insufficient_data
    cvss = record["cvss"]
    if record["vuln_status"] is None or cvss is None:
        report["decision"] = "insufficient_data"
        return report

    # Оцінка є — переносимо її дані у звіт.
    report.update(
        cvss_version=cvss["version"],
        score=cvss["score"],
        score_source=cvss["source"],
        vector=cvss["vector"],
    )

    # Дивимось на поле свого варіанта
    field = rule["field"]
    observed = cvss["data"].get(field, _MISSING)
    # Поля немає - теж insufficient_data
    if observed is _MISSING:
        report["decision"] = "insufficient_data"
        return report
    # Поле є, але значення не з таблиці CVSS
    if not isinstance(observed, str) or observed not in ALLOWED_VALUES[field]:
        raise ValueError(f"cvssData.{field} має недопустиме значення")

    report["observed"] = observed
    matches = cvss["score"] >= rule["threshold"] and observed == rule["expected"]
    # 4) Обидві умови виконані -> review (переглянути) 5) Інакше -> other
    report["decision"] = "review" if matches else "other"
    return report
