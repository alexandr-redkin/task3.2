from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import ipaddress
import secrets

class Severity(Enum):
    INFO = 1
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class EventParseError(Exception):
    """Пользовательское исключение для ошибок парсинга событий."""
    pass

@dataclass(frozen=True, order=True)
class SecurityEvent:
    timestamp: datetime
    source_ip: ipaddress.IPv4Address = field(compare=False)
    user: str = field(compare=False)
    action: str = field(compare=False)
    severity: Severity = field(compare=False)

    def __post_init__(self):
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("Timestamp должен содержать информацию о часовом поясе (UTC-aware).")
        if not self.action or not self.action.strip():
            raise ValueError("Поле action не может быть пустым.")

    @classmethod
    def from_dict(cls, d: dict) -> "SecurityEvent":
        try:
            return cls(
                timestamp=datetime.fromisoformat(d["timestamp"]),
                source_ip=ipaddress.ip_address(d["source_ip"]),
                user=d["user"],
                action=d["action"],
                severity=Severity[d["severity"].upper()]
            )
        except Exception as e:
            raise EventParseError(f"Не удалось распарсить событие из словаря: {e}") from e

class Secret:
    def __init__(self, value: str):
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __str__(self) -> str:
        return 'Secret("********")'

    def __repr__(self) -> str:
        return 'Secret("********")'

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secret):
            return NotImplemented
        return secrets.compare_digest(self._value, other._value)

    def __hash__(self) -> int:
        return hash(self._value)