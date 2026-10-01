#Завдання 2: Аналізатор журналів веб-сервера (Nginx/Apache Access Log)

from __future__ import annotations

import csv
import json
import logging
import re
from collections import Counter, defaultdict #розумні словники, які вміють рахувати к-сть
from dataclasses import asdict, dataclass # швидкий спосіб ств класи-контейнери для даних
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote

# Регулярний вираз для парсингу рядків access.log
LOG_LINE_REGEX = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\d+|-)"
)

# Словник з шаблонами, за якими ми будемо ловити хакерів
ATTACK_PATTERNS: dict[str, re.Pattern[str]] = {
    #SQLi: шукаємо команди баз даних (union select, drop table) або обманки (' OR 1=1)
    "SQLi": re.compile(
        r"(?:union\s+select|or\s+['\"]?1['\"]?\s*=\s*['\"]?1|'--|;\s*drop\s+table)",
        re.IGNORECASE,
    ),
    # Directory Traversal: шукаємо спроби вийти з папки (../) або крадіжку файлу паролів Linux (/etc/passwd)
    "Directory Traversal": re.compile(
        r"(?:\.\./|\.\.\\|/etc/passwd|/etc/shadow)",
        re.IGNORECASE,
    ),
    # XSS: шукаємо вставки JavaScript коду (тег <script>, alert тощо)
    "XSS": re.compile(
        r"(?:<script[^>]*>|javascript:|onerror\s*=|onload\s*=|alert\s*\()",
        re.IGNORECASE,
    ),
}
# Створюємо зручну "картку" для зберігання одного розібраного рядка з журналу.
# frozen=True забороняє змінювати дані після їх запису сюди.

@dataclass(frozen=True)
class LogEntry:
    """Модель одного запису журналу веб-сервера."""

    ip: str
    timestamp: datetime
    method: str
    uri: str
    status: int
    size: int
    # Ця властивість просто склеює метод (напр. GET) і шлях (напр. /index.html) для красивого виводу
    @property
    def request_line(self) -> str:
        """Повертає рядок запиту (HTTP-метод та URI)."""
        return f"{self.method} {self.uri}"

# Картка для збереження інформації, якщо ми знайшли атаку.
@dataclass(frozen=True)
class AttackAlert:
    """Модель виявленої підозри на атаку."""

    attack_type: str #яка саме атака
    ip: str # з якої айпішки
    timestamp: str #коли
    request: str #що саме намагалися зробити
    status: int #що відповів сервер


def parse_log_line(line: str) -> LogEntry | None:
    #прикладаємо наш регулярний вираз до рядка
    match = LOG_LINE_REGEX.match(line.strip())
    #якшо рядок не підходить до регулярного виразу-ігноруєм його
    if not match:
        return None
    #витягує текстову дату і перетворюєм її на точний час
    raw_ts = match.group("timestamp")
    dt = datetime.strptime(raw_ts, "%d/%b/%Y:%H:%M:%S %z")
    #витягує розмір
    raw_size = match.group("size")
    size = int(raw_size) if raw_size.isdigit() else 0
    #пакуєм все, що витягли у нашу LogEntry і вертаєм її
    return LogEntry(
        ip=match.group("ip"),
        timestamp=dt,
        method=match.group("method"),
        uri=match.group("uri"),
        status=int(match.group("status")),
        size=size,
    )

# Функція, яка перевіряє, чи є в запиті ознаки хакерської атаки
def detect_attacks(entry: LogEntry) -> list[AttackAlert]:
    decoded_uri = unquote(entry.uri)
    alerts: list[AttackAlert] = []
    #перебирає всі шаблони атак
    for attack_type, pattern in ATTACK_PATTERNS.items():
        #перевіряє чи є шкідливий код у сирому запиті або розкодованому
        if pattern.search(entry.uri) or pattern.search(decoded_uri):
            #якщо є, то створюєм тривогу і додаєм у список 
            alerts.append(
                AttackAlert(
                    attack_type=attack_type,
                    ip=entry.ip,
                    timestamp=entry.timestamp.isoformat(),
                    request=entry.request_line,
                    status=entry.status,
                )
            )
    return alerts

# функція, яка відкидає записи логів, якщо вони не потрапляють у вказаний час
def filter_by_time(
    entries: list[LogEntry],
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> list[LogEntry]:
    """Фільтрує записи логу за заданим часовим інтервалом"""
    filtered: list[LogEntry] = []
    for entry in entries:
        # тимчасово прибираємо часовий пояс для простого порівняння часу
        entry_naive = entry.timestamp.replace(tzinfo=None)
        # якщо запис стався раніше заданого старту, пропускаємо його
        if start_time is not None and entry_naive < start_time:
            continue
        # Якщо запис стався пізніше заданого кінця — пропускаємо його
        if end_time is not None and entry_naive > end_time:
            continue
        # Якщо все ок, залишаємо запис
        filtered.append(entry)
    return filtered

# Функція, яка зберігає фінальні результати у файл джейсон або ссв
def export_report(
    output_path: Path,
    report_format: str,
    total_entries: int,
    time_range: tuple[str, str],
    top_error_ips: list[dict[str, object]],
    alerts: list[AttackAlert],
) -> None:
    # створення папки для звіту, якщо її ще немає
    output_path.parent.mkdir(parents=True, exist_ok=True)
    #якщо юзер захотів звіт у джейсон 
    if report_format == "json":
        #складаєм всі дані в словник
        payload = {
            "total_entries": total_entries,
            "time_range": {"start": time_range[0], "end": time_range[1]},
            "top_error_ips": top_error_ips,
            "detected_attacks": [asdict(alert) for alert in alerts],
        }
        #записуєм цей словник у файл у гарному вигляді
        output_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        #якщо юзер захотів звіт у вигляді таблиці
    elif report_format == "csv":
        #відкриваєм файл для запису таблиці
        with output_path.open("w", newline="", encoding="utf-8") as csv_file:
            #пишемо заголовки колонок
            writer = csv.writer(csv_file)
            writer.writerow(
                ["category", "ip", "details", "status_or_count", "timestamp"]
            )
            #пишем ынфу про айпі з помилками
            for item in top_error_ips:
                writer.writerow(
                    [
                        "ERROR_IP",
                        item["ip"],
                        json.dumps(item["status_breakdown"]),
                        item["total_errors"],
                        "",
                    ]
                )
            #пишем інфу про знайдені атаки    
            for alert in alerts:
                writer.writerow(
                    [
                        f"ATTACK_{alert.attack_type}",
                        alert.ip,
                        alert.request,
                        alert.status,
                        alert.timestamp,
                    ]
                )
    else:
        #якшо вказали невідомий формат(кидаєм помилку)
        raise ValueError(f"Непідтримуваний формат звіту: {report_format}")

#це головна функцыя( керує всім процесом від початку до кінця)
def analyze_access_log(
    log_file: Path,
    output_file: Path,
    min_status: int = 400,
    top_n: int = 5,
    report_format: str = "json",
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> None:
    #Виконує повний аналіз access.log, виводить статистику та зберігає звіт
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    logger = logging.getLogger("access_log_analyzer")
    # якщо файлу журналу немає на диску, повідомляємо про це і зупиняємо програму
    if not log_file.exists() or not log_file.is_file():
        logger.error("Файл логу не знайдено: %s", log_file)
        raise FileNotFoundError(f"Файл логу не знайдено: {log_file}")

    logger.info("Loading access log from %s...", log_file.as_posix())
    # будемо зберігати всі розібрані рядки журналу
    entries: list[LogEntry] = []
    # відкриває файл журналу і йдемо по ньому рядок за рядком
    with log_file.open("r", encoding="utf-8") as file:
        for line_num, line in enumerate(file, start=1):
            if not line.strip(): #пропускаєм порожні рядки
                continue
            parsed = parse_log_line(line)#пробуєм розібрати рядок
            if parsed is None:
                #якщо регулярний вираз не підійшов, пишем попередження, але продовжуєм роботу
                logger.warning("Пропущено некоректний рядок #%d", line_num)
                continue
            #зберігаєм розібраний запис до списку
            entries.append(parsed)
    #фільтруємо записи, якщо юзер вказав конкретний час
    entries = filter_by_time(entries, start_time=start_time, end_time=end_time)
    #визначаєм, яким часовий проміжок охоплюють запис
    if entries:
        start_str = min(e.timestamp for e in entries).strftime("%Y-%m-%d %H:%M:%S")
        end_str = max(e.timestamp for e in entries).strftime("%Y-%m-%d %H:%M:%S")
    else:
        start_str, end_str = "N/A", "N/A"

    logger.info(
        "Processed %d log entries from %s to %s.",
        len(entries),
        start_str,
        end_str,
    )

    error_ip_counter: Counter[str] = Counter()
    ip_status_breakdown: dict[str, Counter[int]] = defaultdict(Counter)
    detected_alerts: list[AttackAlert] = []

    for entry in entries:
        if entry.status >= min_status:
            error_ip_counter[entry.ip] += 1
            ip_status_breakdown[entry.ip][entry.status] += 1
            # одночасно перевіряєм цей рядок на наявність хакерських атак
        detected_alerts.extend(detect_attacks(entry))
    # .most_common(top_n) автоматично сортує IP за кількістю помилок і бере найкращих (найгірших)
    top_ips = error_ip_counter.most_common(top_n)
    #виводить на екран топ айпі адрес з помилками
    print(f"\n=== Top-{top_n} IP Addresses with Error Statuses (4xx/5xx) ===")
    top_error_ips_data: list[dict[str, object]] = []
    for ip, total_err in top_ips:
        breakdown = ip_status_breakdown[ip]
        #склеює статуси для красивого виводу
        breakdown_str = ", ".join(
            f"{code}: {count}" for code, count in sorted(breakdown.items())
        )
        print(f"{ip:<15} : {total_err} errors ({breakdown_str})")
        #зберігаєм цю інфу, щоб потім записати у файл
        top_error_ips_data.append(
            {
                "ip": ip,
                "total_errors": total_err,
                "status_breakdown": dict(sorted(breakdown.items())),
            }
        )
    #виводить на екран знайдені атаки
    print("\n=== Detected Attack Signatures ===")
    if not detected_alerts:
        print("Сигнатур атак не виявлено.")
    else:
        for alert in detected_alerts:
            print(
                f"[ALERT] Potential {alert.attack_type} attack "
                f'from {alert.ip}: "{alert.request}"'
            )

    print()
    #зберігаэм всі результати у файл
    export_report(
        output_path=output_file,
        report_format=report_format.lower(),
        total_entries=len(entries),
        time_range=(start_str, end_str),
        top_error_ips=top_error_ips_data,
        alerts=detected_alerts,
    )
    logger.info("Analysis report saved to %s", output_file.as_posix())
