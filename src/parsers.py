import json
import datetime
import ipaddress
from src.models import SecurityEvent, Severity

class LogParser:
    def parse(self, line: str) -> SecurityEvent:
        raise NotImplementedError
        
    def parse_line(self, line: str) -> SecurityEvent:
        return self.parse(line)

    @classmethod
    def for_format(cls, format_name: str):
        parser = PARSERS_REGISTRY.get(format_name.lower())
        if not parser:
            raise ValueError("Неизвестный формат логов")
        return parser

class AuthLogParser(LogParser):
    def parse(self, line: str) -> SecurityEvent:
        parts = line.strip().split(';')
        if len(parts) >= 5:
            try:
                ts = datetime.datetime.fromisoformat(parts[0])
            except Exception:
                ts = datetime.datetime.now(datetime.timezone.utc)
            
            try:
                ip = ipaddress.ip_address(parts[1])
            except Exception:
                ip = ipaddress.ip_address("127.0.0.1")
                
            user = parts[2]
            action = parts[3]
            sev_str = parts[4].upper()
            try:
                sev = Severity[sev_str]
            except Exception:
                sev = Severity.INFO
        else:
            ts = datetime.datetime.now(datetime.timezone.utc)
            ip = ipaddress.ip_address("127.0.0.1")
            user = "unknown"
            action = "unknown"
            sev = Severity.INFO
            # Заменили WARNING на HIGH для угроз брутфорса
            if "Failed password" in line or "Invalid user" in line or "failed_login" in line.lower():
                sev = Severity.HIGH

        return SecurityEvent(
            timestamp=ts,
            source_ip=ip,
            user=user,
            action=action,
            severity=sev
        )

class SshAuthParser(AuthLogParser):
    pass

class JsonLogParser(LogParser):
    def parse(self, line: str) -> SecurityEvent:
        try:
            data = json.loads(line)
            ts_str = data.get("timestamp")
            if ts_str:
                try:
                    ts = datetime.datetime.fromisoformat(ts_str)
                except Exception:
                    ts = datetime.datetime.now(datetime.timezone.utc)
            else:
                ts = datetime.datetime.now(datetime.timezone.utc)

            ip_str = data.get("source_ip", "127.0.0.1")
            try:
                ip = ipaddress.ip_address(ip_str)
            except Exception:
                ip = ipaddress.ip_address("127.0.0.1")

            user = data.get("user", "unknown")
            action = data.get("action", "unknown")

            sev_val = data.get("severity", "INFO")
            try:
                sev = Severity[sev_val.upper()]
            except Exception:
                sev = Severity.INFO

            return SecurityEvent(
                timestamp=ts,
                source_ip=ip,
                user=user,
                action=action,
                severity=sev
            )
        except Exception:
            return SecurityEvent(
                timestamp=datetime.datetime.now(datetime.timezone.utc),
                source_ip=ipaddress.ip_address("127.0.0.1"),
                user="unknown",
                action="malformed",
                severity=Severity.LOW
            )

class JsonLineParser(JsonLogParser):
    pass

# Реестр парсеров объявлен после описания всех классов
PARSERS_REGISTRY = {
    "ssh": SshAuthParser(),
    "auth": SshAuthParser(),
    "json": JsonLineParser(),
    "jsonl": JsonLineParser()
}

def get_parser_for_source(source_type: str) -> LogParser:
    parser = PARSERS_REGISTRY.get(source_type.lower())
    if not parser:
        raise ValueError("Неизвестный формат логов")
    return parser