# Mini-SIEM Security Framework

Мини-SIEM — это модульная система анализа событий безопасности (SIEM), предназначенная для сборки логов, нормализации данных, выявления угроз и доставки оповещений (алертов).

## 📁 Структура репозитория

```text
minisiem/
├── data/
│   └── logs/                 # Директория для файлов логов (.ssh, .json и др.)
├── src/                      # Исходный код системы
│   ├── __init__.py
│   ├── models.py             # SecurityEvent, Severity, Secret
│   ├── parsers.py            # LogParser (иерархия и реестр парсеров)
│   ├── rules.py              # DetectionEngine, BruteForcerRule, OffHoursLoginRule
│   ├── sinks.py              # ConsoleSink, JsonLinesSink, MultiSink (AlertSink Protocol)
│   ├── notifier_lsp.py       # Нотификаторы с соблюдением принципа LSP
│   └── cli.py                # Исполняемый консольный интерфейс (CLI)
├── tests/                    # Модульные и контрактные тесты
│   ├── __init__.py
│   └── test_minisiem.py      # Набор тестов pytest
├── config.json               # Файл конфигурации порогов и путей
├── watermark.json            # Файл отслеживания прогресса инкрементального чтения
└── README.md                 # Документация проекта