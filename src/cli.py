import argparse
import json
import os
from src.parsers import get_parser_for_source
from src.rules import DetectionEngine, BruteForcerRule, OffHoursLoginRule
from src.sinks import ConsoleSink, JsonLineSink, MultiSink

def load_watermark(path="watermark.json"):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_watermark(watermark, path="watermark.json"):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(watermark, f, indent=4)

def main():
    parser = argparse.ArgumentParser(description="Mini-SIEM CLI Orchestrator")
    parser.add_argument("--config", default="config.json", help="Path to config file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed execution steps and affected data")
    args = parser.parse_args()

    if args.verbose:
        print("[VERBOSE] Загрузка конфигурации из файла:", args.config)

    with open(args.config, "r", encoding="utf-8") as f:
        config = json.load(f)

    watermark = load_watermark(config.get("watermark_file", "watermark.json"))
    
    # Инициализация приемников алертов
    sinks = [ConsoleSink()]
    alerts_file = config.get("alerts_output", "alerts_output.jsonl")
    sinks.append(JsonLineSink(alerts_file))
    sink = MultiSink(sinks)

    # Инициализация движка правил
    threshold = config.get("brute_force_threshold", 3)
    rules = [
        BruteForcerRule(threshold=threshold),
        OffHoursLoginRule()
    ]
    engine = DetectionEngine(rules)

    all_events = []
    sources = config.get("sources", [])

    if args.verbose:
        print(f"[VERBOSE] Найдено источников логов в конфигурации: {len(sources)}")

    # Шаг 1: Чтение и парсинг логов
    for src in sources:
        name = src.get("name")
        path = src.get("path")
        fmt = src.get("format")

        if args.verbose:
            print(f"\n[PARSING] Обработка источника: '{name}' (формат: {fmt}, путь: {path})")

        parser_obj = get_parser_for_source(fmt)
        last_pos = watermark.get(path, 0)

        if not os.path.exists(path):
            if args.verbose:
                print(f"[WARNING] Файл не найден: {path}")
            continue

        with open(path, "r", encoding="utf-8") as f:
            f.seek(last_pos)
            lines = f.readlines()
            new_pos = f.tell()

        watermark[path] = new_pos

        if args.verbose:
            print(f"[INFO] Прочитано новых строк: {len(lines)} (смещение байт: {last_pos} -> {new_pos})")

        for idx, line in enumerate(lines, 1):
            line_str = line.strip()
            if not line_str:
                continue
            event = parser_obj.parse_line(line_str)
            all_events.append(event)
            if args.verbose:
                print(f"  -> [Событие #{idx}] Время: {event.timestamp}, IP: {event.source_ip}, Пользователь: {event.user}, Действие: {event.action}, Угроза: {event.severity.name}")

    save_watermark(watermark, config.get("watermark_file", "watermark.json"))

    if args.verbose:
        print(f"\n[ANALYSIS] Всего нормализовано событий для анализа: {len(all_events)}")
        print("[ENGINE] Запуск правил детекции угроз (engine.run)...")

    # Шаг 2: Анализ правил через корректный метод run()
    alerts = engine.run(all_events)

    if args.verbose:
        print(f"[ALERTS] Сгенерировано алертов безопасности: {len(alerts)}")

    for alert in alerts:
        sink.send(alert)

    print("SIEM processing completed successfully.")

if __name__ == "__main__":
    main()