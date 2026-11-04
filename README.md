# Mini-SIEM Security Framework
1. Project Overview
1.1. What is Mini-SIEM?

Mini-SIEM (Mini Security Information and Event Management) is a lightweight Security Information and Event Management system implemented in Python.
Its primary purpose is to automatically collect, process, analyze, and correlate security events received from different sources.
In a real IT infrastructure, almost every device and software application generates event logs.

For example:

A server records user login attempts.
An operating system logs authentication failures.
A firewall records network connections.
A web server stores information about incoming requests.
A database management system records access to data.
Antivirus software logs detected malicious files.
An access-control system records user activities.
All these events may contain useful information for information security specialists.
However, there is a significant challenge: logs are generated in different formats, have different structures, and may contain thousands or even millions of records.
This is the problem that SIEM systems are designed to address.
The Mini-SIEM processing workflow consists of the following stages:
Collecting log data from various sources.
Reading new log entries.
Parsing records and extracting relevant information.
Converting data into a unified format.
Analyzing events for suspicious activity.
Detecting potential security threats.
Generating security alerts.
Saving results for further analysis.
Therefore, Mini-SIEM acts as a small centralized analytical tool for security monitoring.

1.2. Why is the project called Mini-SIEM?

Full-scale enterprise SIEM platforms, such as Splunk and IBM QRadar, provide a wide range of capabilities:
Collecting data from thousands of devices.
Centralized log storage.
Network traffic analysis.
Correlation of events from different sources.
Detection of sophisticated attacks.
Integration with incident-response systems.
Visualization of events through interactive dashboards.
Automation of investigation workflows.
Building a full-scale SIEM system requires substantial computing resources, infrastructure, and development time.
Mini-SIEM is a simplified implementation of the core principles behind such systems.

This project focuses on the following components:
Component
Purpose
Log Ingestion
Collecting log records
Parsing
Parsing log entries
Normalization
Converting events into a unified structure
Detection
Identifying potential threats
Correlation
Comparing and correlating multiple events
Alerting
Generating security alerts
Storage
Saving processing results
Testing
Verifying that the system works correctly
It is important to understand that Mini-SIEM is not a replacement for a full-scale enterprise SIEM platform. It is an educational implementation of its fundamental architectural principles.

1.3. Main Project Objective
The main objective of the project is to develop a modular system that can automatically detect potential information security incidents by analyzing event logs.
To achieve this objective, the project must implement several tasks.

Task 1. Data Collection
Develop a mechanism for retrieving information from different log files.

Task 2. Data Processing
Create parsers capable of extracting information from records in different formats.

Task 3. Normalization
Convert the retrieved records into a unified data structure.

Task 4. Security Analysis
Implement mechanisms for detecting suspicious events.

Task 5. Event Correlation
Enable the system to analyze multiple events together and identify patterns that may indicate cyberattacks.

Task 6. Alerting
Develop a mechanism for generating and storing security alerts.

Task 7. Testing
Verify the correctness of each software component through automated tests.

2. Mini-SIEM Architecture

The project architecture follows a modular design.
This means that each part of the system is responsible for a specific task and can be developed, tested, and modified independently of the other components.
The central component is the command-line interface, src/cli.py, which controls the sequence of operations.
The configuration file, config.json, defines the system's operating parameters, including log sources, input formats, and output destinations.
2.1. Overall Workflow
The Mini-SIEM processing pipeline consists of the following stages:

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

3. Log Ingestion
Log ingestion is the first stage of the Mini-SIEM processing pipeline.
Its purpose is to collect log records from configured sources and provide them to the parsing component.
A log source can be a file containing authentication events, system messages, application logs, or other security-related information.

3.1. Incremental Log Reading
One of the important features of Mini-SIEM is incremental log ingestion.
Instead of reading the entire log file every time the program runs, the system reads only newly appended records.
This approach improves performance and reduces unnecessary data processing.
For example, consider a log file containing the following records:
2026-11-04T08:00:00Z;192.168.1.10;admin;LOGIN\_FAILED
2026-11-04T08:01:00Z;192.168.1.15;user1;LOGIN\_SUCCESS
2026-11-04T08:02:00Z;192.168.1.20;root;LOGIN\_FAILED

3.2. Watermark Mechanism
To achieve incremental processing, Mini-SIEM uses a watermark mechanism.
A watermark is a saved position indicating how much of a log file has already been processed.
The system starts reading from byte position 768 instead of returning to the beginning of the file.
After successfully processing the new records, it updates the watermark.

The general algorithm is:
1. Open the configured log file.
2. Retrieve its previously saved reading position.
3. Move the file pointer to that position.
4. Read newly appended records.
5. Pass the records to the parser.
6. Update the saved reading position.
This mechanism makes log processing more efficient, especially when dealing with large files.

Important implementation considerations:
\- The watermark should be updated only after successful processing.
\- The system should handle missing or inaccessible files.
\- File truncation and log rotation should be considered.
\- The reading position should be stored persistently if it must survive program restarts.

4. Log Parsing
Log parsing is the second major stage of the processing pipeline.
Its purpose is to transform raw text records into structured information that can be analyzed by the system.
The parsing functionality is implemented in src/parsers.py.
Mini-SIEM supports multiple log formats.

4.1. Semicolon-Delimited Records
The first supported format consists of records where individual fields are separated by semicolons.

4.2. SSH Authentication Logs
The second supported format is the traditional SSH authentication log format.
SSH (Secure Shell) is a protocol used for secure remote access to systems.
Authentication logs can contain information about successful and unsuccessful login attempts.

4.3. JSON Event Logs
The third supported format is JSON (JavaScript Object Notation).
JSON is a structured data format commonly used by applications, APIs, and security monitoring tools.

4.4. Why Multiple Parsers Are Necessary
Different systems generate different types of logs.
A security monitoring tool must therefore be capable of processing heterogeneous data sources.
Supporting multiple formats makes Mini-SIEM more flexible and adaptable to different environments.
The parsing layer separates the details of individual log formats from the rest of the application.
This means that the detection engine does not need to know whether an event originally came from an SSH log, a semicolon-delimited file, or a JSON document.
All events are converted into a common structure.

5. Event Normalization and Data Models
After parsing, the extracted information must be converted into a unified representation.
This process is called event normalization.
The corresponding data model is defined in src/models.py.

5.1. SecurityEvent
The central data structure is called SecurityEvent.
It represents a normalized security event regardless of its original log format.
A normalized event may contain the following attributes:
Attribute	Description
timestamp	Date and time when the event occurred
source\_ip	IP address associated with the event
username	User account involved in the event
action	Action or activity recorded
severity	Security severity level

For example, the following three records may represent the same type of security event:
\- A semicolon-delimited record.
\- An SSH authentication log entry.
\- A JSON event.
After parsing and normalization, all of them can be represented using the same SecurityEvent structure.

5.2. UTC Timestamps
The system uses UTC (Coordinated Universal Time) for event timestamps.
UTC provides a consistent time reference regardless of the geographical location of the system generating the logs.
This is particularly important when correlating events from multiple servers located in different time zones.
