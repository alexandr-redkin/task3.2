import ipaddress
from datetime import datetime, timezone
import pytest

from src.models import EventParseError, Secret, SecurityEvent, Severity
from src.notifier_lsp import EmailNotifier, SmsNotifier, WebhookNotifier
from src.parsers import JsonLineParser, LogParser, SshAuthParser
from src.rules import Alert, BruteForcerRule, DetectionEngine, OffHoursLoginRule
from src.sinks import ConsoleSink, MultiSink


# === Тесты модели SecurityEvent и Secret (C2.1 & C2.4) ===

def test_security_event_valid():
    dt = datetime.now(timezone.utc)
    ev = SecurityEvent(
        timestamp=dt,
        source_ip=ipaddress.IPv4Address("192.168.1.10"),
        user="admin",
        action="failed_login",
        severity=Severity.HIGH,
    )
    assert ev.user == "admin"
    assert ev.severity == Severity.HIGH


def test_security_event_naive_timestamp_raises():
    naive_dt = datetime.now()  # Без информации о часовом поясе (naive)
    with pytest.raises(ValueError, match="UTC-aware"):
        SecurityEvent(
            timestamp=naive_dt,
            source_ip=ipaddress.IPv4Address("127.0.0.1"),
            user="user",
            action="login",
            severity=Severity.LOW,
        )


def test_security_event_empty_action_raises():
    dt = datetime.now(timezone.utc)
    with pytest.raises(ValueError, match="action не может быть пустым"):
        SecurityEvent(
            timestamp=dt,
            source_ip=ipaddress.IPv4Address("127.0.0.1"),
            user="user",
            action="   ",
            severity=Severity.LOW,
        )


def test_secret_masking_and_equality():
    secret_val = "super_secret_api_token_12345"
    sec1 = Secret(secret_val)
    sec2 = Secret(secret_val)

    # 1. Проверка маскирования в строках (C2.4)
    assert "********" in str(sec1)
    assert "********" in repr(sec1)
    assert secret_val not in str(sec1)

    # 2. Безопасное чтение только через reveal()
    assert sec1.reveal() == secret_val

    # 3. Проверка сравнения и хэширования
    assert sec1 == sec2
    assert hash(sec1) == hash(sec2)


# === Контрактные тесты для парсеров логов (C2.2) ===

def test_parser_registry():
    ssh_parser = LogParser.for_format("ssh")
    json_parser = LogParser.for_format("json")
    assert isinstance(ssh_parser, SshAuthParser)
    assert isinstance(json_parser, JsonLineParser)

    with pytest.raises(ValueError, match="Неизвестный формат логов"):
        LogParser.for_format("unknown_format")


def test_ssh_auth_parser_valid_line():
    parser = SshAuthParser()
    line = "2026-11-04T08:00:00+00:00;192.168.1.50;root;failed_login;HIGH"
    event = parser.parse_line(line)
    assert event is not None
    assert event.user == "root"
    assert event.source_ip == ipaddress.IPv4Address("192.168.1.50")
    assert event.severity == Severity.HIGH


def test_json_line_parser_valid_line():
    parser = JsonLineParser()
    line = '{"timestamp": "2026-11-04T09:00:00+00:00", "source_ip": "10.0.0.1", "user": "alice", "action": "login", "severity": "MEDIUM"}'
    event = parser.parse_line(line)
    assert event is not None
    assert event.user == "alice"
    assert event.severity == Severity.MEDIUM


# === Тесты полиморфного движка правил (C2.3) ===

def test_brute_force_rule_trigger():
    dt = datetime.now(timezone.utc)
    events = [
        SecurityEvent(dt, ipaddress.IPv4Address("1.1.1.1"), "admin", "failed_login", Severity.HIGH),
        SecurityEvent(dt, ipaddress.IPv4Address("1.1.1.1"), "admin", "failed_login", Severity.HIGH),
        SecurityEvent(dt, ipaddress.IPv4Address("1.1.1.1"), "admin", "failed_login", Severity.HIGH),
    ]
    rule = BruteForcerRule(threshold=3)
    alerts = rule.evaluate(events)
    assert len(alerts) == 1
    assert alerts[0].rule_name == "BruteForcerRule"
    assert "1.1.1.1" in alerts[0].description


def test_detection_engine_resilience():
    class BrokenRule:
        def __init__(self):
            self.name = "BrokenRule"

        def evaluate(self, events):
            raise RuntimeError("Симулируемый сбой в правиле!")

    rule_good = BruteForcerRule(threshold=1)
    engine = DetectionEngine([BrokenRule(), rule_good])

    dt = datetime.now(timezone.utc)
    events = [SecurityEvent(dt, ipaddress.IPv4Address("2.2.2.2"), "user", "failed_login", Severity.HIGH)]

    # Движок не должен падать из-за сломанного правила (C2.3)
    alerts = engine.run(events)
    assert len(alerts) == 1
    assert alerts[0].rule_name == "BruteForcerRule"


# === Контрактные тесты для Notifiers на соблюдение LSP (C2.5) ===

@pytest.mark.parametrize("notifier_cls", [EmailNotifier, SmsNotifier, WebhookNotifier])
def test_notifiers_contract_lsp(notifier_cls):
    notifier = notifier_cls()
    long_msg = "A" * 200  # Сообщение больше 160 символов

    # Ни один подкласс не должен выбрасывать исключения при вызове send(str)
    # и обязателен возврат значения типа bool
    result = notifier.send(long_msg)
    assert isinstance(result, bool)