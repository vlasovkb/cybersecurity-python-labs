"""Завдання 2, варіант 3: валідатор та аналізатор конфігурацій правил фаєрвола.

Утиліта читає правила з JSON або CSV, перевіряє їх коректність (IP, маски,
порти, дії), шукає дублікати, суперечливі та небезпечні дозволяючі правила,
друкує звіт, а результати зберігає у два JSON-файли: звіт аудиту та очищений
список правил.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import logging
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

LOGGER = logging.getLogger("lab02.firewall")

# --- Регулярні вирази (ASCII-режим, щоб \d не збігався з не-латинськими цифрами) ---
OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"  # 0-255 без ведучих нулів
MASK = r"(?:3[0-2]|[12]?\d)"  # 0-32
IPV4_RE = re.compile(rf"{OCTET}(?:\.{OCTET}){{3}}", re.ASCII)
ADDRESS_RE = re.compile(rf"{OCTET}(?:\.{OCTET}){{3}}(?:/{MASK})?", re.ASCII)
PORT_RE = re.compile(r"[0-9]{1,5}", re.ASCII)

ANY = "ANY"
VALID_ACTIONS = ("ALLOW", "DENY")
SENSITIVE_PORTS = {"21": "FTP", "22": "SSH", "23": "Telnet", "3389": "RDP"}
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
DEFAULT_REPORT_NAME = "fw_audit_report.json"

# Імена полів у вхідних файлах (регістр і пробіли навколо назв ігноруються).
FIELD_ALIASES = {
    "id": ("id", "rule_id"),
    "source": ("source", "source_ip", "source ip", "src"),
    "destination": ("destination", "destination_ip", "destination ip", "dst"),
    "port": ("port",),
    "action": ("action",),
}

# Рівень логування для кожного типу знахідки.
FINDING_LEVELS = {
    "INVALID": logging.ERROR,
    "HIGH-RISK": logging.ERROR,
    "CONFLICT": logging.WARNING,
    "DUPLICATE": logging.WARNING,
}


class AuditError(Exception):
    """Помилка читання/запису файлів або некоректні аргументи."""


# --- Моделі даних --------------------------------------------------------------
@dataclass(frozen=True)
class FirewallRule:
    rule_id: int
    source: str
    destination: str
    port: str
    action: str

    def describe(self) -> str:
        return f"{self.action} {self.source} -> {self.destination}:{self.port}"

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.rule_id,
            "source": self.source,
            "destination": self.destination,
            "port": self.port,
            "action": self.action,
        }


@dataclass(frozen=True)
class Finding:
    kind: str  # INVALID | DUPLICATE | CONFLICT | HIGH-RISK
    rule_ids: list[int]
    message: str

    def to_dict(self) -> dict[str, object]:
        return {"type": self.kind, "rule_ids": self.rule_ids, "message": self.message}


@dataclass
class AuditReport:
    total_rules: int
    conflicts_checked: bool
    invalid_ip: list[Finding] = field(default_factory=list)
    invalid_other: list[Finding] = field(default_factory=list)
    duplicates: list[Finding] = field(default_factory=list)
    conflicts: list[Finding] = field(default_factory=list)
    high_risk: list[Finding] = field(default_factory=list)
    cleaned_rules: list[FirewallRule] = field(default_factory=list)

    def all_findings(self) -> list[Finding]:
        invalid = sorted(
            self.invalid_ip + self.invalid_other, key=lambda f: f.rule_ids[0]
        )
        return invalid + self.duplicates + self.conflicts + self.high_risk

    def to_dict(self, source_file: Path) -> dict[str, object]:
        return {
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "source_file": str(source_file),
            "summary": {
                "total_rules": self.total_rules,
                "invalid_ip_formats": len(self.invalid_ip),
                "invalid_port_or_action": len(self.invalid_other),
                "duplicates": len(self.duplicates),
                "conflicts": len(self.conflicts) if self.conflicts_checked else None,
                "conflicts_checked": self.conflicts_checked,
                "high_risk": len(self.high_risk),
                "cleaned_rules": len(self.cleaned_rules),
            },
            "findings": {
                "invalid_ip_formats": [f.to_dict() for f in self.invalid_ip],
                "invalid_port_or_action": [f.to_dict() for f in self.invalid_other],
                "duplicates": [f.to_dict() for f in self.duplicates],
                "conflicts": [f.to_dict() for f in self.conflicts],
                "high_risk": [f.to_dict() for f in self.high_risk],
            },
        }


# --- Читання вхідних даних -----------------------------------------------------
def _text(value: object) -> str:
    return "" if value is None else str(value).strip()


def _pick(record: dict[str, object], field_name: str) -> object:
    for alias in FIELD_ALIASES[field_name]:
        if alias in record:
            return record[alias]
    return None


def _read_json(path: Path) -> list[object]:
    with path.open(encoding="utf-8-sig") as handle:
        data = json.load(handle)
    if isinstance(data, dict) and isinstance(data.get("rules"), list):
        data = data["rules"]
    if not isinstance(data, list):
        raise AuditError(f"{path}: expected a JSON array of rules")
    return data


def _read_csv(path: Path) -> list[object]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _record_to_rule(record: object, position: int) -> FirewallRule:
    if not isinstance(record, dict):
        raise AuditError(f"record #{position} is not an object with rule fields")
    normalized = {
        str(key).strip().lower(): value for key, value in record.items() if key
    }

    raw_id = _text(_pick(normalized, "id"))
    try:
        rule_id = int(raw_id) if raw_id else position
    except ValueError:
        rule_id = position

    port = _text(_pick(normalized, "port"))
    return FirewallRule(
        rule_id=rule_id,
        source=_text(_pick(normalized, "source")),
        destination=_text(_pick(normalized, "destination")),
        port=ANY if port.upper() == ANY else port,
        action=_text(_pick(normalized, "action")).upper(),
    )


def load_rules(path: Path) -> list[FirewallRule]:
    """Читає правила з JSON або CSV. Некоректні значення полів не відкидаються тут,
    а потрапляють у звіт під час валідації."""
    if not path.is_file():
        raise AuditError(f"rules file not found: {path}")
    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            records = _read_json(path)
        elif suffix == ".csv":
            records = _read_csv(path)
        else:
            raise AuditError(
                f"unsupported rules file format: {suffix or '(no extension)'}"
            )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, csv.Error) as exc:
        raise AuditError(f"cannot read {path}: {exc}") from exc
    return [
        _record_to_rule(record, position) for position, record in enumerate(records, 1)
    ]


# --- Валідація -------------------------------------------------------------------
def is_valid_address(value: str) -> bool:
    """IPv4 або IPv4/маска (0-32); ``ANY`` означає будь-яку адресу."""
    return value.upper() == ANY or ADDRESS_RE.fullmatch(value) is not None


def is_valid_port(value: str) -> bool:
    if value.upper() == ANY:
        return True
    return PORT_RE.fullmatch(value) is not None and 1 <= int(value) <= 65535


def address_error(value: str, role: str) -> str | None:
    """Текст помилки для адреси або None, якщо адреса коректна."""
    if is_valid_address(value):
        return None
    host, separator, mask = value.partition("/")
    if separator and IPV4_RE.fullmatch(host):
        return f"invalid {role} mask '/{mask}' in '{value}'"
    return f"invalid {role} IP '{value}'"


def validate_rule(rule: FirewallRule) -> tuple[list[str], list[str]]:
    """Повертає (помилки IP/масок, інші помилки: порт і дія)."""
    ip_errors = [
        error
        for error in (
            address_error(rule.source, "source"),
            address_error(rule.destination, "destination"),
        )
        if error
    ]
    other_errors = []
    if not is_valid_port(rule.port):
        other_errors.append(f"invalid port '{rule.port}'")
    if rule.action not in VALID_ACTIONS:
        other_errors.append(f"invalid action '{rule.action}' (expected ALLOW or DENY)")
    return ip_errors, other_errors


# --- Аналіз правил ---------------------------------------------------------------
def normalize_address(value: str) -> str:
    """Канонічна адреса: ``10.0.0.5`` -> ``10.0.0.5/32``, ``ANY`` -> ``0.0.0.0/0``."""
    if value.upper() == ANY:
        return "0.0.0.0/0"
    return str(ipaddress.ip_network(value, strict=False))


def traffic_key(rule: FirewallRule) -> tuple[str, str, str]:
    """Ключ потоку трафіку: (джерело, призначення, порт) без урахування дії."""
    return (
        normalize_address(rule.source),
        normalize_address(rule.destination),
        rule.port,
    )


def _label(rules: list[FirewallRule]) -> str:
    ids = ", ".join(f"#{rule.rule_id}" for rule in rules)
    return f"Rule {ids}" if len(rules) == 1 else f"Rules {ids}"


def high_risk_reasons(rule: FirewallRule) -> list[str]:
    """Причини, через які дозволяюче правило вважається небезпечним."""
    if rule.action != "ALLOW":
        return []
    open_source = ipaddress.ip_network(normalize_address(rule.source)).prefixlen == 0
    any_port = rule.port == ANY
    if open_source and any_port:
        return ["unlimited exposure (any source, any port)"]
    if open_source:
        service = SENSITIVE_PORTS.get(rule.port)
        note = f" ({service} publicly accessible)" if service else ""
        return [f"source 0.0.0.0/0 is open to the whole Internet{note}"]
    if any_port:
        return ["all ports are allowed"]
    return []


def audit_rules(rules: list[FirewallRule], *, check_conflicts: bool) -> AuditReport:
    report = AuditReport(total_rules=len(rules), conflicts_checked=check_conflicts)

    # 1. Валідація: некоректні правила не беруть участі в подальшому аналізі.
    valid: list[FirewallRule] = []
    for rule in rules:
        ip_errors, other_errors = validate_rule(rule)
        if ip_errors or other_errors:
            message = f"Rule #{rule.rule_id}: " + "; ".join(ip_errors + other_errors)
            finding = Finding("INVALID", [rule.rule_id], message)
            (report.invalid_ip if ip_errors else report.invalid_other).append(finding)
        else:
            valid.append(rule)

    # 2. Дублікати: однакові (джерело, призначення, порт, дія). Лишаємо перше.
    by_full_key: defaultdict[tuple[str, ...], list[FirewallRule]] = defaultdict(list)
    for rule in valid:
        by_full_key[(*traffic_key(rule), rule.action)].append(rule)
    duplicate_ids: set[int] = set()
    for group in by_full_key.values():
        original, *copies = group
        for copy in copies:
            duplicate_ids.add(copy.rule_id)
            message = (
                f"Rule #{copy.rule_id} duplicates Rule #{original.rule_id} "
                f"({original.describe()})"
            )
            report.duplicates.append(
                Finding("DUPLICATE", [copy.rule_id, original.rule_id], message)
            )
    report.cleaned_rules = [rule for rule in valid if rule.rule_id not in duplicate_ids]

    # 3. Суперечності: той самий потік дозволено в одному правилі й заборонено в іншому.
    if check_conflicts:
        by_traffic: defaultdict[tuple[str, str, str], list[FirewallRule]] = defaultdict(
            list
        )
        for rule in report.cleaned_rules:
            by_traffic[traffic_key(rule)].append(rule)
        for group in by_traffic.values():
            allowed = [rule for rule in group if rule.action == "ALLOW"]
            denied = [rule for rule in group if rule.action == "DENY"]
            if allowed and denied:
                message = (
                    f"{_label(allowed)} ({allowed[0].describe()}) conflicts with "
                    f"{_label(denied)} ({denied[0].describe()})"
                )
                ids = [rule.rule_id for rule in group]
                report.conflicts.append(Finding("CONFLICT", ids, message))

    # 4. Небезпечні дозволяючі правила.
    for rule in report.cleaned_rules:
        reasons = high_risk_reasons(rule)
        if reasons:
            message = f"Rule #{rule.rule_id}: {rule.describe()} - {'; '.join(reasons)}"
            report.high_risk.append(Finding("HIGH-RISK", [rule.rule_id], message))
    return report


# --- Виведення, логування, збереження -------------------------------------------------
class _TagFilter(logging.Filter):
    """Підставляє у запис тег (CONFLICT, HIGH-RISK тощо) або назву рівня."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "tag"):
            record.tag = record.levelname
        return True


def configure_logging(level: str, log_file: Path | None) -> None:
    LOGGER.handlers.clear()
    LOGGER.setLevel(getattr(logging, level))
    LOGGER.propagate = False

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter("[%(tag)s] %(message)s"))
    console.addFilter(_TagFilter())
    LOGGER.addHandler(console)

    if log_file is not None:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
        except OSError as exc:
            raise AuditError(f"cannot open log file {log_file}: {exc}") from exc
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(tag)s] %(message)s")
        )
        file_handler.addFilter(_TagFilter())
        LOGGER.addHandler(file_handler)


def print_report(report: AuditReport) -> None:
    if report.conflicts_checked:
        conflicts_line = f"{len(report.conflicts)} conflicts found"
    else:
        conflicts_line = "skipped (use --check-conflicts)"
    print()
    print("=== Firewall Configuration Audit Report ===")
    print(f"Invalid IP Formats  : {len(report.invalid_ip)}")
    print(f"Invalid Port/Action : {len(report.invalid_other)}")
    print(f"Conflicting Rules   : {conflicts_line}")
    print(f"Duplicate Rules     : {len(report.duplicates)} duplicates found")
    print(f"High-Risk Rules     : {len(report.high_risk)} dangerous ALLOW rules")
    print()
    print("=== Critical Findings ===")
    findings = report.all_findings()
    if not findings:
        print("No findings.")
    for finding in findings:
        LOGGER.log(
            FINDING_LEVELS[finding.kind],
            "%s",
            finding.message,
            extra={"tag": finding.kind},
        )
    print()


def write_json(path: Path, payload: object, *, protect: Path) -> None:
    """Записує JSON. Не дозволяє перезаписати вхідний файл з правилами."""
    if path.resolve() == protect.resolve():
        raise AuditError(f"refusing to overwrite the input file: {path}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
    except OSError as exc:
        raise AuditError(f"cannot write {path}: {exc}") from exc


# --- CLI ---------------------------------------------------------------------------
def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--rules-file",
        type=Path,
        required=True,
        help="path to the rules file (.json or .csv)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help=f"audit report JSON (default: {DEFAULT_REPORT_NAME} next to rules file)",
    )
    parser.add_argument(
        "--cleaned-output",
        type=Path,
        default=None,
        help="cleaned rules JSON (default: <output>_cleaned_rules.json)",
    )
    parser.add_argument(
        "--check-conflicts",
        action="store_true",
        help="also look for conflicting ALLOW/DENY rules",
    )
    parser.add_argument(
        "--log-level",
        type=str.upper,
        choices=LOG_LEVELS,
        default="INFO",
        help="logging level (default: INFO)",
    )
    parser.add_argument(
        "--log-file", type=Path, default=None, help="also write the log to a file"
    )


def run(args: argparse.Namespace) -> int:
    """Виконує аудит. Код завершення: 0 - успіх, 1 - помилка вхідних/вихідних даних."""
    try:
        configure_logging(args.log_level, args.log_file)
        rules_path: Path = args.rules_file
        output_path: Path = args.output or rules_path.with_name(DEFAULT_REPORT_NAME)
        cleaned_path: Path = args.cleaned_output or output_path.with_name(
            f"{output_path.stem}_cleaned_rules.json"
        )

        LOGGER.info("Parsing firewall rules from %s...", rules_path)
        rules = load_rules(rules_path)
        LOGGER.info(
            "Total rules parsed: %d. Validating IP syntax and rule logic...", len(rules)
        )
        report = audit_rules(rules, check_conflicts=args.check_conflicts)
        print_report(report)

        write_json(output_path, report.to_dict(rules_path), protect=rules_path)
        write_json(
            cleaned_path,
            [rule.to_dict() for rule in report.cleaned_rules],
            protect=rules_path,
        )
        LOGGER.info("Security report successfully exported to %s", output_path)
        LOGGER.info(
            "Cleaned rule list (%d rules) saved to %s",
            len(report.cleaned_rules),
            cleaned_path,
        )
        return 0
    except AuditError as exc:
        LOGGER.error("%s", exc)
        return 1
    finally:
        for handler in list(LOGGER.handlers):
            handler.close()
