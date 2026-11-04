import json
import os
import sys
import argparse

from src.parsers import get_parser_for_source
from src.rules import DetectionEngine, BruteForcerRule, OffHoursLoginRule
from src.sinks import ConsoleSink, JsonLineSink, MultiSink
from src.notifier_lsp import NotifierLSP

def load_config(config_path):
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def load_watermark(watermark_path):
    if os.path.exists(watermark_path):
        with open(watermark_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_watermark(watermark_path, watermark):
    with open(watermark_path, 'w', encoding='utf-8') as f:
        json.dump(watermark, f, indent=2)

def main():
    parser = argparse.ArgumentParser(description="Mini-SIEM Security Framework CLI")
    parser.add_argument("--config", default="config.json", help="Path to configuration file")
    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f"Error: Config file not found at {args.config}")
        sys.exit(1)

    config = load_config(args.config)
    watermark_path = config.get("watermark_file", "watermark.json")
    watermarks = load_watermark(watermark_path)

    # Инициализация движка правил обнаружения с передачей правил в конструктор
    engine = DetectionEngine([
        BruteForcerRule(threshold=config.get("brute_force_threshold", 3)),
        OffHoursLoginRule()
    ])

    # Настройка приемников (sinks) для алертов
    sinks_list = [ConsoleSink()]
    alert_output = config.get("alert_output", "alerts_output.jsonl")
    if alert_output:
        sinks_list.append(JsonLineSink(alert_output))
    
    if config.get("lsp_enabled", True):
        sinks_list.append(NotifierLSP())

    sink = MultiSink(sinks_list)

    # Обработка источников логов из конфигурации
    sources = config.get("sources", [])
    for src_conf in sources:
        file_path = src_conf.get("path")
        source_type = src_conf.get("type")

        if not file_path or not os.path.exists(file_path):
            print(f"Warning: Log file not found: {file_path}")
            continue

        last_pos = watermarks.get(file_path, 0)
        log_parser = get_parser_for_source(source_type)

        if not log_parser:
            print(f"Warning: No parser found for type {source_type}")
            continue

        events = []
        with open(file_path, 'r', encoding='utf-8') as f:
            f.seek(last_pos)
            for line in f:
                line = line.strip()
                if line:
                    event = log_parser.parse(line)
                    if event:
                        events.append(event)
            watermarks[file_path] = f.tell()

        # Анализ событий и отправка алертов
        alerts = engine.analyze(events)
        for alert in alerts:
            sink.send(alert)

    # Сохранение прогресса чтения логов
    save_watermark(watermark_path, watermarks)
    print("SIEM processing completed successfully.")

if __name__ == "__main__":
    main()