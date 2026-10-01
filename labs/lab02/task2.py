"""Завдання 2 (варіант 1): аналізатор журналів веб-сервера"""

from __future__ import annotations

import csv
import json
import logging
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote_plus  # для декодування юрл

LOG_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
REPORT_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
MAX_HTTP_STATUS = 599
# трафарет
LOG_LINE_REGEX = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<uri>.+?)\s+(?P<protocol>HTTP/\d(?:\.\d)?)"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\d+|-)"
)

# словник, де ключі-назви атак, а зн. це регулярні вирази для їхнього пошуку
ATTACK_PATTERNS: dict[str, re.Pattern[str]] = {
    # SQLi: union select, ' OR 1=1, коментар після лапки, ; drop table
    "SQLi": re.compile(
        r"(?:union\s+select|\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1|'--|;\s*drop\s+table)",
        re.IGNORECASE,  # ігнор регістру
    ),
    # Directory Traversal: ../, ..\ та доступ до файлів паролів Linux
    "Directory Traversal": re.compile(
        r"(?:\.\./|\.\.\\|/etc/passwd|/etc/shadow)",
        re.IGNORECASE,
    ),
    # XSS: тег <script>, javascript:, обробники подій, alert(
    "XSS": re.compile(
        r"(?:<script[^>]*>|javascript:|onerror\s*=|onload\s*=|alert\s*\()",
        re.IGNORECASE,
    ),
}


# ств незмінний клас даних
@dataclass(frozen=True)
class LogEntry:  # модель для зберігання одного розібраного рядка логу
    ip: str  # змінна для айпішки
    timestamp: datetime  # змінна для часу
    method: str  # хттп метод
    uri: str  # для запитаного шляху
    status: int  # для статус-коду відповіді
    size: int  # розмір відповіді в байтах

    @property  # дек, дозволяє викликати метод як звичайну змінну
    def request_line(self) -> str:  # метод, який об'єднує метод на юрі
        return f"{self.method} {self.uri}"


# ств незмінний клас даних для атак
@dataclass(frozen=True)
class AttackAlert:  # модель для зберігання інфи про знайдену загрозу
    attack_type: str  # тип атаки
    ip: str  # IP-адреса джерела
    timestamp: str  # час запиту
    request: str  # метод та юрі
    status: int  # відповідь сервера


# функція приймає рядок і повертає об'єкт логентрі або нічого
def parse_log_line(line: str) -> LogEntry | None:
    match = LOG_LINE_REGEX.match(
        line.strip()
    )  # прибирає пробіли по краях і застосовуєм регулярний вираз
    if not match:
        return None
    try:
        dt = datetime.strptime(  # noqa: DTZ007
            match.group("timestamp"), LOG_TIME_FORMAT
        )  # конвертуємо текст часу у справжній об'єкт часу
    except ValueError:
        return None
    raw_size = match.group("size")  # дістаєм розмір відповіді
    size = (
        int(raw_size) if raw_size.isdigit() else 0
    )  # якщо розмір це число, конвертуємо в int, інакше ставимо 0
    return LogEntry(  # ств і вертаєм готовий об'єкт Логентрі(витягнуту айпішку,час, нттп,юрі,конвертує статус у число, передає розмір)
        ip=match.group("ip"),
        timestamp=dt,
        method=match.group("method"),
        uri=match.group("uri"),
        status=int(match.group("status")),
        size=size,
    )


# функція шукає атаки в конкретному записі
def detect_attacks(entry: LogEntry) -> list[AttackAlert]:
    decoded_uri = unquote_plus(entry.uri)  # декодуєм юрл
    alerts: list[AttackAlert] = []  # ств пустий список для знайдених атак
    for (
        attack_type,
        pattern,
    ) in ATTACK_PATTERNS.items():  # перебирає кожну атаку з словника
        if pattern.search(entry.uri) or pattern.search(
            decoded_uri
        ):  # шукає збіг у закодов або розкод юрі
            alerts.append(  # якщо найшло, додаєм нову тривогу в список
                AttackAlert(  # ств об'єкт тривоги
                    attack_type=attack_type,  # тип
                    ip=entry.ip,  # айпі
                    timestamp=entry.timestamp.isoformat(),  # час
                    request=entry.request_line,  # який саме запит
                    status=entry.status,  # код відповіді
                )
            )
    return alerts


# функ для вирівнювання час поясів
def _align(entry_time: datetime, bound: datetime) -> datetime:
    return (
        entry_time if bound.tzinfo is not None else entry_time.replace(tzinfo=None)
    )  # якщо межа має часовий пояс(залишаєм як є,інакше прибираєм пояс із часу логів)


# функ для відбору логів за проміжком часу
def filter_by_time(
    entries: list[LogEntry],  # приймає список усіх логів
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> list[LogEntry]:

    filtered: list[LogEntry] = []  # пустий список для підходящих записів
    for entry in entries:  # перебирає всі наявні логи
        if start_time is not None and _align(entry.timestamp, start_time) < start_time:
            continue
        if end_time is not None and _align(entry.timestamp, end_time) > end_time:
            continue
        filtered.append(entry)
    return filtered


# функ для збереження результату у файл
def export_report(
    output_path: Path,  # шлях
    report_format: str,  # формат(джейсон або ссв)
    total_entries: int,  # загальна к-сть опрацьованих рядків
    time_range: tuple[str, str],  # проміжок часу(початок, кінець)
    top_error_ips: list[dict[str, object]],  # топ айпі адрес з помилками
    alerts: list[AttackAlert],  # список знайдених атак
) -> None:

    output_path.parent.mkdir(parents=True, exist_ok=True)
    if report_format == "json":
        payload = {
            "total_entries": total_entries,  # загальна к-сть
            "time_range": {"start": time_range[0], "end": time_range[1]},  # додає час
            "top_error_ips": top_error_ips,  # топ айпішкм
            "detected_attacks": [
                asdict(alert) for alert in alerts
            ],  # об'єкти атакалерт у звичайні словники перетворює
        }
        output_path.write_text(  # записує текст у файл
            json.dumps(
                payload, indent=2, ensure_ascii=False
            ),  # конверт слов у джейсон текст з відступами
            encoding="utf-8",
        )
    elif report_format == "csv":
        with output_path.open(
            "w", newline="", encoding="utf-8"
        ) as csv_file:  # відкриває файл для запису
            writer = csv.writer(csv_file)  # ств тулу для запису рядків
            writer.writerow(  # заголовки колонок
                ["category", "ip", "details", "status_or_count", "timestamp"]
            )
            for item in top_error_ips:  # для кожного проблемного айпі
                writer.writerow(  # статистика в в окремий рядок таблиці
                    [
                        "ERROR_IP",  # категорія
                        item["ip"],  # сама айпішка
                        json.dumps(item["status_breakdown"]),  # які статуси були
                        item["total_errors"],  # загальна к-сть
                        "",  # для часу
                    ]
                )
            for alert in alerts:  # для кожної знайденої атаки
                writer.writerow(
                    [
                        f"ATTACK_{alert.attack_type}",  # категорія
                        alert.ip,  # айпі зловмисника
                        alert.request,  # який запит
                        alert.status,  # код відповіді
                        alert.timestamp,  # час атаки
                    ]
                )
    else:  # якшо юзер передав невідомий формат
        raise ValueError(f"Непідтримуваний формат звіту: {report_format}")


# головна функ, яка керує всім процесом
def analyze_access_log(
    log_file: Path,  # де лежить файл аксес.лог
    output_file: Path,  # куда зберегти результат
    min_status: int = 400,  # з якого статус-коду вважати запит помилкою
    top_n: int = 5,  # скільки айпі адрес виводити в топ
    report_format: str = "json",  # у якому форматі зберегти звіт
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> None:
    logger = logging.getLogger("access_log_analyzer")
    if not log_file.is_file():  # якщо вказано файлу не існує
        logger.error("Файл логу не знайдено: %s", log_file)
        raise FileNotFoundError(f"Файл логу не знайдено: {log_file}")

    logger.info("Loading access log from %s...", log_file.as_posix())  # початок роботи
    entries: list[LogEntry] = []  # список, куди будуть складені успішно розібрані логи
    # errors="replace": биті байти в логах атак не повинні зупиняти аналіз
    with log_file.open("r", encoding="utf-8", errors="replace") as file:
        for line_num, line in enumerate(
            file, start=1
        ):  # читає файл по одному рядку,рахуючи їх номери
            if not line.strip():
                continue
            parsed = parse_log_line(line)  # розбирає рядок нашою функ
            if parsed is None:  # якшо рядок не розібрався
                logger.warning("Пропущено некоректний рядок #%d", line_num)
                continue
            entries.append(
                parsed
            )  # якшо все гуд, додаєм розібраний лог у загальний список

    entries = filter_by_time(
        entries, start_time=start_time, end_time=end_time
    )  # фільтруєм зібрані логи за вказаним часом

    if entries:  # якшо після фільтрації залишилися записи
        start_str = min(e.timestamp for e in entries).strftime(
            REPORT_TIME_FORMAT
        )  # знаходе найстаріший і найновіший запис
        end_str = max(e.timestamp for e in entries).strftime(REPORT_TIME_FORMAT)
    else:
        start_str, end_str = "N/A", "N/A"
    logger.info(  # виводить повідомлення про к-сть оброблених записів
        "Processed %d log entries from %s to %s.", len(entries), start_str, end_str
    )

    error_ip_counter: Counter[str] = Counter()  # лічильник айпі адрес з помилками
    ip_status_breakdown: dict[str, Counter[int]] = defaultdict(
        Counter
    )  # ств словника, де для кожного айпі буде свій лічильник статус-кодів
    detected_alerts: list[
        AttackAlert
    ] = []  # ств пустий список для зберігання інцидентів безпеки

    for entry in entries:  # перебирає всі валідні записи
        if (
            min_status <= entry.status <= MAX_HTTP_STATUS
        ):  # якшо статус-код підпадає в діапазон помилки
            error_ip_counter[entry.ip] += (
                1  # додає +1 до загальної к-сть помилок для цього айпі
            )
            ip_status_breakdown[entry.ip][entry.status] += (
                1  # який саме код помилки у цьому айпі
            )
        # на атаки перевіряється кожен запис незалежно від статусу
        detected_alerts.extend(
            detect_attacks(entry)
        )  # викл функ пошуку атак і + знайдене до загального спику

    top_ips = error_ip_counter.most_common(
        top_n
    )  # просить лічильник дати топ_н найгірших айпішок
    print(f"\n=== Top-{top_n} IP Addresses with Error Statuses (4xx/5xx) ===")
    top_error_ips_data: list[dict[str, object]] = []  # список для збереження топ айпі
    for ip, total_err in top_ips:  # перебираєм кожну айпі з топу
        breakdown = ip_status_breakdown[ip]  # деталі помилок
        breakdown_str = ", ".join(  # об'єднуєм
            f"{code}: {count}"
            for code, count in sorted(breakdown.items())  # сортуєм статуси
        )
        print(f"{ip} - {total_err} errors ({breakdown_str})")
        top_error_ips_data.append(  # додаєм цю інфу в словник для майб експорту у файл
            {
                "ip": ip,
                "total_errors": total_err,  # записуєм к-сть
                "status_breakdown": dict(sorted(breakdown.items())),  # деталі статусів
            }
        )

    print("\n=== Detected Attack Signatures ===")
    if not detected_alerts:  # якшо список атак порожні
        print("Сигнатур атак не виявлено.")
    else:
        for alert in detected_alerts:  # перебираєм кожну тривогу
            print(
                f"[ALERT] Potential {alert.attack_type} attack "  # тип атаки
                f'from {alert.ip}: "{alert.request}"'  # з якої айпішки і який запит
            )
    print()

    export_report(
        output_path=output_file,
        report_format=report_format.lower(),
        total_entries=len(entries),
        time_range=(start_str, end_str),
        top_error_ips=top_error_ips_data,
        alerts=detected_alerts,
    )
    logger.info("Analysis report saved to %s", output_file.as_posix())
