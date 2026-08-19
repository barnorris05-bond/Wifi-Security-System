# Wi-Fi Security & Spectrum Analytics Platform

A modular Wi-Fi discovery, security risk analysis, and spectrum analytics platform built with Python, SQLite, and Streamlit.

## Features

- **Modular Scanner Architecture:** Decoupled scanner backends and parsers for Linux Wi-Fi discovery.
- **Security Risk Engine:** Rule-based assessment of wireless security configurations using encryption and authentication factors.
- **Spectrum Analytics:** Visualization of channel distribution, frequency bands, and signal strength.
- **SQLite Persistence:** Stores scan sessions and network assessment data for historical analysis.
- **Streamlit Dashboard:** Interactive overview, network details, and spectrum analytics.
- **Automated Testing:** Unit and integration tests for models, parsers, scanners, database operations, and security analysis.
- **Sample Dataset:** Offline demonstration mode using structured sample scan data.

## Project Architecture

`	ext
WiFi-Security-Analytics/
├── app.py
├── main.py
│
├── config/
│   └── risk_rules.py
│
├── models/
│   ├── network.py
│   ├── assessment.py
│   └── scan.py
│
├── scanner/
│   ├── interface.py
│   ├── base_scanner.py
│   ├── scanner_factory.py
│   ├── nmcli_scanner.py
│   ├── iw_scanner.py
│   ├── iwlist_scanner.py
│   └── parsers/
│       ├── base_parser.py
│       ├── nmcli_parser.py
│       ├── iw_parser.py
│       └── iwlist_parser.py
│
├── analyzer/
│   ├── security.py
│   ├── signal.py
│   ├── channel.py
│   └── frequency.py
│
├── database/
│   ├── database.py
│   └── schema.sql
│
├── dashboard/
│   ├── overview.py
│   ├── networks.py
│   ├── analytics.py
│   ├── history.py
│   └── components.py
│
├── reports/
│   ├── pdf_report.py
│   ├── csv_export.py
│   └── json_export.py
│
├── data/
│   ├── sample_scan.json
│   └── sample_scan_history.json
│
├── tests/
│   ├── fixtures/
│   ├── test_models.py
│   ├── test_parsers.py
│   ├── test_scanners.py
│   ├── test_security.py
│   ├── test_database.py
│   └── test_pipeline.py
│
└── docs/
    ├── architecture.md
    ├── methodology.md
    └── security_model.md
