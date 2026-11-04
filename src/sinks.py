import json

class AlertSink:
    def send(self, alert):
        raise NotImplementedError

class ConsoleSink(AlertSink):
    def send(self, alert):
        print(f"[ALERT] [{alert.severity.value}] {alert.rule_name}: {alert.message} (Source: {alert.source})")

class JsonLineSink(AlertSink):
    def __init__(self, filepath):
        self.filepath = filepath

    def send(self, alert):
        data = {
            "rule_name": alert.rule_name,
            "severity": alert.severity.value,
            "message": alert.message,
            "source": alert.source,
            "timestamp": getattr(alert, "timestamp", None)
        }
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