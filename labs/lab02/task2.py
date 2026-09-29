"""Завдання 2 (Варіант 1): Аналізатор журналів веб-сервера (Nginx/Apache Access Log)."""

from __future__ import annotations

from collections import Counter, defaultdict
import csv
from dataclasses import asdict, dataclass
from datetime import datetime
import json
import logging
from pathlib import Path
import re
from urllib.parse import unquote

# Регулярний вираз для парсингу рядків access.log
LOG_LINE_REGEX = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\d+|-)"
)

# Сигнатури базових атак (SQLi, Directory Traversal, XSS)
ATTACK_PATTERNS: dict[str, re.Pattern[str]] = {
    "SQLi": re.compile(
        r"(?:union\s+select|or\s+['\"]?1['\"]?\s*=\s*['\"]?1|'--|;\s*drop\s+table)",
        re.IGNORECASE,
    ),
    "Directory Traversal": re.compile(
        r"(?:\.\./|\.\.\\|/etc/passwd|/etc/shadow)",
        re.IGNORECASE,
    ),
    "XSS": re.compile(
        r"(?:<script[^>]*>|javascript:|onerror\s*=|onload\s*=|alert\s*\()",
        re.IGNORECASE,
    ),
}


@dataclass(frozen=True)
class LogEntry:
    """Модель одного запису журналу веб-сервера."""

    ip: str
    timestamp: datetime
    method: str
    uri: str
    status: int
    size: int

    @property
    def request_line(self) -> str:
        """Повертає рядок запиту (HTTP-метод та URI)."""
        return f"{self.method} {self.uri}"


@dataclass(frozen=True)
class AttackAlert:
    """Модель виявленої підозри на атаку."""

    attack_type: str
    ip: str
    timestamp: str
    request: str
    status: int


def parse_log_line(line: str) -> LogEntry | None:
    """Розбирає рядок логу за допомогою регулярного виразу."""
    match = LOG_LINE_REGEX.match(line.strip())
    if not match:
        return None

    raw_ts = match.group("timestamp")
    dt = datetime.strptime(raw_ts, "%d/%b/%Y:%H:%M:%S %z")
    raw_size = match.group("size")
    size = int(raw_size) if raw_size.isdigit() else 0

    return LogEntry(
        ip=match.group("ip"),
        timestamp=dt,
        method=match.group("method"),
        uri=match.group("uri"),
        status=int(match.group("status")),
        size=size,
    )


def detect_attacks(entry: LogEntry) -> list[AttackAlert]:
    """Шукає сигнатури SQLi, Directory Traversal та XSS у запиті."""
    decoded_uri = unquote(entry.uri)
    alerts: list[AttackAlert] = []

    for attack_type, pattern in ATTACK_PATTERNS.items():
        if pattern.search(entry.uri) or pattern.search(decoded_uri):
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


def filter_by_time(
    entries: list[LogEntry],
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> list[LogEntry]:
    """Фільтрує записи логу за заданим часовим інтервалом."""
    filtered: list[LogEntry] = []
    for entry in entries:
        entry_naive = entry.timestamp.replace(tzinfo=None)
        if start_time is not None and entry_naive < start_time:
            continue
        if end_time is not None and entry_naive > end_time:
            continue
        filtered.append(entry)
    return filtered


def export_report(
    output_path: Path,
    report_format: str,
    total_entries: int,
    time_range: tuple[str, str],
    top_error_ips: list[dict[str, object]],
    alerts: list[AttackAlert],
) -> None:
    """Експортує результати аналізу у файл формату JSON або CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if report_format == "json":
        payload = {
            "total_entries": total_entries,
            "time_range": {"start": time_range[0], "end": time_range[1]},
            "top_error_ips": top_error_ips,
            "detected_attacks": [asdict(alert) for alert in alerts],
        }
        output_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    elif report_format == "csv":
        with output_path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(
                ["category", "ip", "details", "status_or_count", "timestamp"]
            )
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
        raise ValueError(f"Непідтримуваний формат звіту: {report_format}")


def analyze_access_log(
    log_file: Path,
    output_file: Path,
    min_status: int = 400,
    top_n: int = 5,
    report_format: str = "json",
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> None:
    """Виконує повний аналіз access.log, виводить статистику та зберігає звіт."""
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    logger = logging.getLogger("access_log_analyzer")

    if not log_file.exists() or not log_file.is_file():
        logger.error("Файл логу не знайдено: %s", log_file)
        raise FileNotFoundError(f"Файл логу не знайдено: {log_file}")

    logger.info("Loading access log from %s...", log_file.as_posix())

    entries: list[LogEntry] = []
    with log_file.open("r", encoding="utf-8") as file:
        for line_num, line in enumerate(file, start=1):
            if not line.strip():
                continue
            parsed = parse_log_line(line)
            if parsed is None:
                logger.warning("Пропущено некоректний рядок #%d", line_num)
                continue
            entries.append(parsed)

    entries = filter_by_time(entries, start_time=start_time, end_time=end_time)

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
        detected_alerts.extend(detect_attacks(entry))

    top_ips = error_ip_counter.most_common(top_n)
    print(f"\n=== Top-{top_n} IP Addresses with Error Statuses (4xx/5xx) ===")
    top_error_ips_data: list[dict[str, object]] = []
    for ip, total_err in top_ips:
        breakdown = ip_status_breakdown[ip]
        breakdown_str = ", ".join(
            f"{code}: {count}" for code, count in sorted(breakdown.items())
        )
        print(f"{ip:<15} : {total_err} errors ({breakdown_str})")
        top_error_ips_data.append(
            {
                "ip": ip,
                "total_errors": total_err,
                "status_breakdown": dict(sorted(breakdown.items())),
            }
        )

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
    export_report(
        output_path=output_file,
        report_format=report_format.lower(),
        total_entries=len(entries),
        time_range=(start_str, end_str),
        top_error_ips=top_error_ips_data,
        alerts=detected_alerts,
    )
    logger.info("Analysis report saved to %s", output_file.as_posix())