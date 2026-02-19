"""
========================================================
  Log Parsing Engine — Data Engineering AI Project
  Tools: Pandas · NumPy · Regex · AI Anomaly Detection
========================================================
"""

import re
import numpy as np
import pandas as pd
from datetime import datetime
from pathlib import Path


# ──────────────────────────────────────────────
# 1. LOG FORMAT PATTERNS
# ──────────────────────────────────────────────

LOG_PATTERNS = {
    "apache_common": re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) \S+" '
        r'(?P<status>\d{3}) (?P<bytes>\d+|-)'
    ),
    "apache_error": re.compile(
        r'\[(?P<timestamp>[^\]]+)\] \[(?P<level>\w+)\] '
        r'(?P<message>.+)'
    ),
    "nginx": re.compile(
        r'(?P<ip>\S+) - \S+ \[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) \S+" '
        r'(?P<status>\d{3}) (?P<bytes>\d+) '
        r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
    ),
    "syslog": re.compile(
        r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}) '
        r'(?P<host>\S+) (?P<process>\S+): (?P<message>.+)'
    ),
    "json_log": re.compile(
        r'\{.*"level"\s*:\s*"(?P<level>\w+)".*"message"\s*:\s*"(?P<message>[^"]+)".*\}'
    ),
}


# ──────────────────────────────────────────────
# 2. PARSER CLASS
# ──────────────────────────────────────────────

class LogParser:
    """
    Parses raw log files into structured Pandas DataFrames.
    Supports Apache (common/error), Nginx, Syslog, JSON logs.
    """

    def __init__(self, log_format: str = "apache_common"):
        if log_format not in LOG_PATTERNS:
            raise ValueError(f"Unsupported format. Choose from: {list(LOG_PATTERNS)}")
        self.log_format = log_format
        self.pattern = LOG_PATTERNS[log_format]
        self._raw_lines: list[str] = []
        self._failed_lines: list[str] = []

    # ── File Ingestion ──
    def load_file(self, filepath: str | Path) -> "LogParser":
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            self._raw_lines = f.readlines()
        print(f"[✓] Loaded {len(self._raw_lines):,} lines from '{filepath}'")
        return self

    def load_string(self, raw_text: str) -> "LogParser":
        self._raw_lines = raw_text.strip().splitlines()
        return self

    # ── Core Parse ──
    def parse(self) -> pd.DataFrame:
        records = []
        for line in self._raw_lines:
            match = self.pattern.search(line.strip())
            if match:
                records.append(match.groupdict())
            else:
                self._failed_lines.append(line)

        df = pd.DataFrame(records)
        df = self._cast_dtypes(df)

        parse_rate = len(records) / max(len(self._raw_lines), 1) * 100
        print(f"[✓] Parsed {len(df):,} records  |  {len(self._failed_lines):,} failed  |  {parse_rate:.1f}% success rate")
        return df

    # ── Type Casting ──
    def _cast_dtypes(self, df: pd.DataFrame) -> pd.DataFrame:
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(
                df["timestamp"],
                format="%d/%b/%Y:%H:%M:%S %z",
                errors="coerce",
            )
        if "status" in df.columns:
            df["status"] = pd.to_numeric(df["status"], errors="coerce").astype("Int16")
        if "bytes" in df.columns:
            df["bytes"] = pd.to_numeric(df["bytes"].replace("-", 0), errors="coerce").astype("Int64")
        return df

    @property
    def parse_errors(self) -> list[str]:
        return self._failed_lines


# ──────────────────────────────────────────────
# 3. QUICK DEMO USAGE
# ──────────────────────────────────────────────

SAMPLE_LOGS = """\
192.168.1.1 - frank [10/Oct/2024:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
10.0.0.1 - - [10/Oct/2024:13:56:01 -0700] "POST /api/login HTTP/1.1" 200 512
203.0.113.5 - - [10/Oct/2024:13:56:10 -0700] "GET /admin HTTP/1.1" 403 287
172.16.0.50 - john [10/Oct/2024:13:57:22 -0700] "DELETE /api/users/9 HTTP/1.1" 204 0
192.168.1.1 - frank [10/Oct/2024:13:58:45 -0700] "GET /dashboard HTTP/1.1" 200 8190
10.0.0.1 - - [10/Oct/2024:13:59:11 -0700] "GET /notfound HTTP/1.1" 404 153
203.0.113.5 - - [10/Oct/2024:14:00:30 -0700] "GET /login HTTP/1.1" 200 1024
172.16.0.50 - john [10/Oct/2024:14:01:05 -0700] "PUT /api/config HTTP/1.1" 500 0
"""

if __name__ == "__main__":
    parser = LogParser(log_format="apache_common")
    df = parser.load_string(SAMPLE_LOGS).parse()
    print("\n── Sample DataFrame ──")
    print(df.to_string(index=False))
