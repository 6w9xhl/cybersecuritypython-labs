# Лабораторна робота №4: інтеграція з NVD API та тестування pytest

**Варіант 1** — мережевий вектор атаки.

Правило: `score >= 7.0` **і** `cvssData.attackVector == "NETWORK"` в одній і тій самій
вибраній оцінці CVSS v3.1 (`metrics.cvssMetricV31`). Номер варіанта береться з
`shared/student.py` (`VARIANT_NUMBER`).

`attackVector` описує, звідки зловмисник може експлуатувати вразливість:
`NETWORK` — віддалено через мережу (зокрема інтернет), `ADJACENT_NETWORK` — із суміжної
мережі, `LOCAL` — з локальним доступом, `PHYSICAL` — з фізичним доступом до пристрою.

## Структура

```
labs/lab04/
├── main.py            # CLI: аргументи, load_response(), main(), повідомлення та коди виходу
├── api_client.py      # build_headers(), fetch_response(): один GET до NVD CVE API 2.0
├── analysis.py        # extract_record(), build_report(): перевірка даних і правила варіантів
├── data/
│   └── nvd_sample.json  # синтетична відповідь (CVE-2099-10001) для роботи без мережі
└── tests/
    ├── conftest.py      # заборона справжніх запитів Requests, видалення NVD_API_KEY
    ├── test_analysis.py # модульні тести перевірки даних і правила
    ├── test_api_client.py # тести клієнта з підміною requests.get
    └── test_main.py     # інтеграційні тести CLI (tmp_path, capsys, monkeypatch)
```

## Встановлення

З кореня репозиторію, Python 3.12+:

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows (Linux/macOS: source .venv/bin/activate)
pip install -r requirements.txt
```

## Запуск

Локальний режим (без мережі):

```bash
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
```

Запит до NVD (лише поодинокі ручні запити):

```bash
python -m labs.lab04.main --cve CVE-2021-44228
```

Необов'язковий ключ API передається через змінну середовища `NVD_API_KEY`
(у заголовку `apiKey`, не в URL). Ключ не зберігається у файлах проєкту.

```powershell
$env:NVD_API_KEY = "<ваш ключ>"
```

Аргументи:

- `--cve` — обов'язковий, повний збіг з `CVE-[0-9]{4}-[0-9]{4,}` (з урахуванням регістру);
- `--input` — шлях до локальної відповіді NVD (UTF-8 JSON); якщо задано, мережа не використовується.

Коди завершення: `0` — звіт сформовано (зокрема `not_found`, `insufficient_data`);
`1` — помилка отримання, читання чи перевірки даних; `2` — неправильні аргументи або номер варіанта.

## Формат звіту

У `stdout` виводиться один JSON-об'єкт; повідомлення про помилки — у `stderr`.

| Ключ | Значення |
|------|----------|
| `cve_id` | Запитаний ідентифікатор |
| `variant` | Номер варіанта |
| `description` | Перший непорожній англійський опис або `null` |
| `vuln_status` | Статус NVD або `null` |
| `cvss_version` | `"3.1"` або `null` |
| `score` | `baseScore` вибраної оцінки або `null` |
| `score_source` | `source` вибраної оцінки або `null` |
| `vector` | `vectorString` вибраної оцінки або `null` |
| `rule` | `{"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"}` |
| `observed` | Значення `attackVector` вибраної оцінки або `null` |
| `decision` | `not_found` / `rejected` / `insufficient_data` / `review` / `other` |

Вибір оцінки: перша з `type="Primary"`, а за її відсутності — перша у списку.

Результат для синтетичного файла (варіант 1):

```json
{
  "cve_id": "CVE-2099-10001",
  "variant": 1,
  "description": "Synthetic vulnerability for offline API testing.",
  "vuln_status": "Analyzed",
  "cvss_version": "3.1",
  "score": 9.8,
  "score_source": "nvd@nist.gov",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "rule": {"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"},
  "observed": "NETWORK",
  "decision": "review"
}
```

Стани `other` та `insufficient_data` не означають, що вразливість безпечна; `review` —
відповідність навчальному правилу, а не готовий пріоритет усунення.

## Перевірка

```bash
python -m pytest labs/lab04/tests -q
ruff check labs/lab04
ruff format --check labs/lab04
```

Тести не звертаються до мережі: `conftest.py` видаляє `requests.sessions.Session.request`
перед кожним тестом, а клієнт перевіряється через підміну `api_client.requests.get`.
Тест межі порога (`baseScore` 6.9 / 7.0 / 7.1) падає, якщо замінити `>=` на `>`.

## Ручний запит до NVD

2026-11-12, 08:35 UTC, без ключа API:

```bash
python -m labs.lab04.main --cve CVE-2021-44228
```

Результат (код 0): `vuln_status="Analyzed"`, `score=10.0`, `score_source="nvd@nist.gov"`,
`vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"`, `observed="NETWORK"`,
`decision="review"`. Дані NVD змінюються, тому в автотестах цей результат не закріплено.
