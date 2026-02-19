"""
========================================================
  Log Parsing AI Pipeline — Orchestrator & CLI
  Usage:  python pipeline.py [--file path] [--format fmt]
========================================================
"""

import argparse
import sys
import time
from pathlib import Path

import pandas as pd

from log_parser import LogParser, SAMPLE_LOGS, LOG_PATTERNS
from analysis  import TrafficAnalyzer, AnomalyDetector


# ──────────────────────────────────────────────
# PIPELINE
# ──────────────────────────────────────────────

class LogPipeline:
    """
    End-to-end pipeline:
      Load → Parse → Enrich → Analyze → Report → Export
    """

    def __init__(self, log_format: str = "apache_common",
                 z_threshold: float = 2.5,
                 iqr_factor: float = 1.5):
        self.parser   = LogParser(log_format)
        self.detector = AnomalyDetector(z_threshold, iqr_factor)
        self.analyzer = TrafficAnalyzer(self.detector)
        self.df: pd.DataFrame | None = None

    # ── Step 1: Ingest ──
    def load(self, filepath: str | None = None, raw: str | None = None) -> "LogPipeline":
        if filepath:
            self.parser.load_file(filepath)
        elif raw:
            self.parser.load_string(raw)
        else:
            raise ValueError("Provide either 'filepath' or 'raw' text.")
        return self

    # ── Step 2: Parse ──
    def parse(self) -> "LogPipeline":
        self.df = self.parser.parse()
        return self

    # ── Step 3: Enrich ──
    def enrich(self) -> "LogPipeline":
        if self.df is None:
            raise RuntimeError("Call .parse() first.")
        df = self.df

        # Hour-of-day feature
        if "timestamp" in df.columns:
            df["hour"]    = df["timestamp"].dt.hour
            df["weekday"] = df["timestamp"].dt.day_name()

        # Status class buckets
        if "status" in df.columns:
            bins   = [0, 199, 299, 399, 499, 599]
            labels = ["1xx", "2xx", "3xx", "4xx", "5xx"]
            df["status_class"] = pd.cut(
                df["status"], bins=bins, labels=labels, right=True
            )

        # Path depth
        if "path" in df.columns:
            df["path_depth"] = df["path"].str.count("/")

        self.df = df
        return self

    # ── Step 4: Analyze ──
    def analyze(self):
        if self.df is None:
            raise RuntimeError("Call .parse() first.")
        report = self.analyzer.analyze(self.df)
        self.analyzer.print_report(report)
        return report

    # ── Step 5: Export ──
    def export(self, output_dir: str = ".") -> None:
        if self.df is None:
            raise RuntimeError("Call .parse() first.")
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        parquet_path = out / "parsed_logs.parquet"
        csv_path     = out / "parsed_logs.csv"

        self.df.to_parquet(parquet_path, index=False)
        self.df.to_csv(csv_path, index=False)
        print(f"[✓] Exported → {parquet_path}")
        print(f"[✓] Exported → {csv_path}")

    # ── Full Run ──
    def run(self, filepath=None, raw=None, output_dir="."):
        t0 = time.perf_counter()
        self.load(filepath=filepath, raw=raw).parse().enrich().analyze()
        self.export(output_dir)
        elapsed = time.perf_counter() - t0
        print(f"\n[✓] Pipeline completed in {elapsed:.3f}s\n")


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="Log Parsing AI Pipeline")
    p.add_argument("--file",   type=str, default=None,
                   help="Path to log file (leave blank to use built-in sample)")
    p.add_argument("--format", type=str, default="apache_common",
                   choices=list(LOG_PATTERNS), help="Log format")
    p.add_argument("--out",    type=str, default="output",
                   help="Output directory for exported files")
    p.add_argument("--z",      type=float, default=2.5,
                   help="Z-score anomaly threshold")
    args = p.parse_args()

    pipeline = LogPipeline(log_format=args.format, z_threshold=args.z)
    if args.file:
        pipeline.run(filepath=args.file, output_dir=args.out)
    else:
        print("[i] No --file provided. Running on built-in sample logs.\n")
        pipeline.run(raw=SAMPLE_LOGS, output_dir=args.out)


if __name__ == "__main__":
    main()
