import json
from src.models import SecurityEvent, Severity

class LogParser:
    def parse(self, line: str) -> SecurityEvent:
        raise NotImplementedError

class AuthLogParser(LogParser):
    def parse(self, line: str) -> SecurityEvent:
        severity = Severity.INFO
        event_type = "AUTH_LOG"
        
        if "Failed password" in line or "Invalid user" in line:
            severity = Severity.WARNING
            event_type = "FAILED_LOGIN"
        elif "Accepted password" in line:
            severity = Severity.INFO
            event_type = "SUCCESSFUL_LOGIN"

        return SecurityEvent(
            raw_line=line,
            event_type=event_type,
            severity=severity,
            source="auth.ssh"
        )

class JsonLogParser(LogParser):
    def parse(self, line: str) -> SecurityEvent:
        try:
            data = json.loads(line)
            return SecurityEvent(
                raw_line=line,
                event_type=data.get("event_type", "JSON_EVENT"),
                severity=Severity(data.get("severity", "INFO")),
                source=data.get("source", "events.json"),
                details=data
            )
        except Exception:
            return SecurityEvent(
                raw_line=line,
                event_type="MALFORMED_JSON",
                severity=Severity.LOW,
                source="unknown"
            )

# Реестр парсеров для различных типов источников
PARSERS_REGISTRY = {
    "ssh": AuthLogParser(),
    "auth": AuthLogParser(),
    "json": JsonLogParser()
}

def get_parser_for_source(source_type: str) -> LogParser:
    """Возвращает парсер по строковому идентификатору типа источника."""
    return PARSERS_REGISTRY.get(source_type.lower())