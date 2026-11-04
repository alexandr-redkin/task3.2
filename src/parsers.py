from abc import ABC, abstractmethod
from datetime import datetime
import ipaddress
import json
from src.models import SecurityEvent, Severity

class LogParser(ABC):
    _registry: dict[str, type["LogParser"]] = {}

    def __init_subclass__(cls, fmt: str, **kwargs):
        super().__init_subclass__(**kwargs)
        cls._registry[fmt] = cls

    @classmethod
    def for_format(cls, fmt: str) -> "LogParser":
        parser_cls = cls._registry.get(fmt)
        if not parser_cls:
            raise ValueError(f"Неизвестный формат логов: {fmt}")
        return parser_cls()

    @abstractmethod
    def parse_line(self, line: str) -> SecurityEvent | None:
        pass

    def parse_file(self, path: str) -> tuple[list[SecurityEvent], int]:
        events = []
        malformed_count = 0
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    event = self.parse_line(line.strip())
                    if event:
                        events.append(event)
                    else:
                        malformed_count += 1
                except Exception:
                    malformed_count += 1
        return events, malformed_count

class SshAuthParser(LogParser, fmt="ssh"):
    def parse_line(self, line: str) -> SecurityEvent | None:
        parts = line.split(";")
        if len(parts) < 5:
            return None
        return SecurityEvent(
            timestamp=datetime.fromisoformat(parts[0]),
            source_ip=ipaddress.ip_address(parts[1]),
            user=parts[2],
            action=parts[3],
            severity=Severity[parts[4].upper()]
        )

class JsonLineParser(LogParser, fmt="json"):
    def parse_line(self, line: str) -> SecurityEvent | None:
        try:
            data = json.loads(line)
            return SecurityEvent.from_dict(data)
        except Exception:
            return None