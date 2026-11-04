from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
import logging
from src.models import SecurityEvent, Severity

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class Alert:
    rule_name: str
    severity: Severity
    description: str
    timestamp: datetime

class DetectionRule(ABC):
    def __init__(self, name: str, severity: Severity):
        self.name = name
        self.severity = severity

    @abstractmethod
    def evaluate(self, events: list[SecurityEvent]) -> list[Alert]:
        pass

class BruteForcerRule(DetectionRule):
    def __init__(self, threshold: int = 3, window_seconds: int = 60):
        super().__init__("BruteForcerRule", Severity.HIGH)
        self.threshold = threshold
        self.window_seconds = window_seconds

    def evaluate(self, events: list[SecurityEvent]) -> list[Alert]:
        alerts = []
        attempts = {}
        for ev in events:
            if "failed_login" in ev.action.lower():
                attempts.setdefault((ev.source_ip, ev.user), []).append(ev.timestamp)
        for (ip, user), timestamps in attempts.items():
            if len(timestamps) >= self.threshold:
                alerts.append(Alert(self.name, self.severity, f"Брутфорс от {ip} для пользователя {user}", timestamps[-1]))
        return alerts

class OffHoursLoginRule(DetectionRule):
    def __init__(self, start_hour: int = 8, end_hour: int = 20):
        super().__init__("OffHoursLoginRule", Severity.MEDIUM)
        self.start_hour = start_hour
        self.end_hour = end_hour

    def evaluate(self, events: list[SecurityEvent]) -> list[Alert]:
        alerts = []
        for ev in events:
            if "successful_login" in ev.action.lower():
                hour = ev.timestamp.hour
                if hour < self.start_hour or hour >= self.end_hour:
                    alerts.append(Alert(self.name, self.severity, f"Вход в нерабочее время ({hour}:00) пользователем {ev.user}", ev.timestamp))
        return alerts

class DetectionEngine:
    def __init__(self, rules: list[DetectionRule]):
        self.rules = rules

    def run(self, events: list[SecurityEvent]) -> list[Alert]:
        all_alerts = []
        for rule in self.rules:
            try:
                all_alerts.extend(rule.evaluate(events))
            except Exception as e:
                logger.error(f"Ошибка в правиле {rule.name}: {e}")
        return all_alerts