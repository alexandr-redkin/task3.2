from typing import Protocol, runtime_checkable
import json
import logging
from src.rules import Alert

logger = logging.getLogger(__name__)

@runtime_checkable
class AlertSink(Protocol):
    def send(self, alert: Alert) -> None:
        ...

class ConsoleSink:
    def send(self, alert: Alert) -> None:
        print(f"[ALERT] [{alert.severity.name}] {alert.rule_name}: {alert.description} at {alert.timestamp}")

class JsonLinesSink:
    def __init__(self, filepath: str):
        self.filepath = filepath

    def send(self, alert: Alert) -> None:
        data = {
            "rule_name": alert.rule_name,
            "severity": alert.severity.name,
            "description": alert.description,
            "timestamp": alert.timestamp.isoformat()
        }
        with open(self.filepath, "a", encoding="utf-8") as f:
            f.write(json.dumps(data) + "\n")

class MultiSink:
    def __init__(self, sinks: list[AlertSink]):
        self.sinks = sinks

    def send(self, alert: Alert) -> None:
        for sink in self.sinks:
            try:
                sink.send(alert)
            except Exception as e:
                logger.error(f"Ошибка в синк-обработчике: {e}")