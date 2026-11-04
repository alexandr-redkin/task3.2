import json
import os

class AlertSink:
    def send(self, alert):
        raise NotImplementedError

class ConsoleSink(AlertSink):
    def send(self, alert):
        # Безопасно получаем значение степени угрозы (.value или имя)
        sev = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
        # Поддерживаем как description, так и message
        desc = getattr(alert, "description", getattr(alert, "message", ""))
        source_str = getattr(alert, "source", "system")
        
        print(f"[ALERT] [{sev}] {alert.rule_name}: {desc} (Source: {source_str})")

class JsonLineSink(AlertSink):
    def __init__(self, filepath="alerts_output.jsonl"):
        self.filepath = filepath

    def send(self, alert):
        sev = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
        desc = getattr(alert, "description", getattr(alert, "message", ""))
        
        data = {
            "rule_name": alert.rule_name,
            "severity": sev,
            "description": desc,
            "source": getattr(alert, "source", "system"),
            "timestamp": alert.timestamp.isoformat() if hasattr(alert.timestamp, "isoformat") else str(alert.timestamp)
        }
        
        dir_name = os.path.dirname(os.path.abspath(self.filepath))
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
            
        with open(self.filepath, 'a', encoding='utf-8') as f:
            f.write(json.dumps(data, ensure_ascii=False) + "\n")

# Алиас на случай, если где-то используется вариант с буквой 's'
JsonLinesSink = JsonLineSink

class MultiSink(AlertSink):
    def __init__(self, sinks):
        self.sinks = sinks

    def send(self, alert):
        for sink in self.sinks:
            sink.send(alert)