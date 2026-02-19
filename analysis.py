"""
========================================================
  Log Analysis Engine — NumPy-Powered Intelligence
  Features: Anomaly Detection · Traffic Analysis · AI Scoring
========================================================
"""

import numpy as np
import pandas as pd
from dataclasses import dataclass, field


# ──────────────────────────────────────────────
# 1. DATA CLASSES
# ──────────────────────────────────────────────

@dataclass
class AnomalyResult:
    """Container for a detected anomaly."""
    index: int
    ip: str
    score: float
    reason: str
    severity: str  # "low" | "medium" | "high" | "critical"


@dataclass
class TrafficReport:
    """Summary statistics for a parsed log DataFrame."""
    total_requests:   int
    unique_ips:       int
    error_rate_pct:   float
    top_paths:        pd.Series
    top_ips:          pd.Series
    status_dist:      pd.Series
    bytes_stats:      dict
    anomalies:        list[AnomalyResult] = field(default_factory=list)


# ──────────────────────────────────────────────
# 2. ANOMALY DETECTOR
# ──────────────────────────────────────────────

class AnomalyDetector:
    """
    NumPy-based anomaly detection using Z-score, IQR, and
    request-rate heuristics.  No ML framework required.
    """

    def __init__(self, z_threshold: float = 2.5, iqr_factor: float = 1.5):
        self.z_threshold = z_threshold
        self.iqr_factor = iqr_factor

    # ── Z-Score outlier flag (bytes) ──
    def _zscore_flags(self, series: np.ndarray) -> np.ndarray:
        mean = np.nanmean(series)
        std  = np.nanstd(series)
        if std == 0:
            return np.zeros(len(series), dtype=bool)
        z = np.abs((series - mean) / std)
        return z > self.z_threshold

    # ── IQR outlier flag ──
    def _iqr_flags(self, series: np.ndarray) -> np.ndarray:
        q1 = np.nanpercentile(series, 25)
        q3 = np.nanpercentile(series, 75)
        iqr = q3 - q1
        lower, upper = q1 - self.iqr_factor * iqr, q3 + self.iqr_factor * iqr
        return (series < lower) | (series > upper)

    # ── Per-IP request rate heuristic ──
    def _rate_flags(self, df: pd.DataFrame, threshold: int = 50) -> pd.Series:
        counts = df.groupby("ip")["ip"].transform("count")
        return counts > threshold

    # ── Score & Classify ──
    def _severity(self, score: float) -> str:
        if score >= 0.75: return "critical"
        if score >= 0.50: return "high"
        if score >= 0.25: return "medium"
        return "low"

    def detect(self, df: pd.DataFrame) -> list[AnomalyResult]:
        results: list[AnomalyResult] = []
        bytes_arr = df["bytes"].fillna(0).to_numpy(dtype=float)

        z_flags   = self._zscore_flags(bytes_arr)
        iqr_flags = self._iqr_flags(bytes_arr)
        rate_flags = self._rate_flags(df) if "ip" in df.columns else pd.Series(False, index=df.index)
        error_flags = df["status"].ge(400) if "status" in df.columns else pd.Series(False, index=df.index)

        for i, row in df.iterrows():
            reasons, raw_score = [], 0.0

            if z_flags[i]:
                reasons.append(f"Byte outlier (Z-score)")
                raw_score += 0.3
            if iqr_flags[i]:
                reasons.append("IQR byte anomaly")
                raw_score += 0.2
            if rate_flags.iloc[i]:
                reasons.append("High request rate from IP")
                raw_score += 0.4
            if error_flags.iloc[i]:
                code = int(row["status"])
                reasons.append(f"HTTP {code} error")
                raw_score += 0.15 if code < 500 else 0.35

            score = min(raw_score, 1.0)
            if score > 0:
                results.append(AnomalyResult(
                    index    = i,
                    ip       = row.get("ip", "unknown"),
                    score    = round(score, 3),
                    reason   = " + ".join(reasons),
                    severity = self._severity(score),
                ))

        results.sort(key=lambda r: r.score, reverse=True)
        return results


# ──────────────────────────────────────────────
# 3. TRAFFIC ANALYZER
# ──────────────────────────────────────────────

class TrafficAnalyzer:
    """
    Computes aggregate statistics and insights from a log DataFrame.
    Uses Pandas groupby + NumPy for vectorised calculations.
    """

    def __init__(self, detector: AnomalyDetector | None = None):
        self.detector = detector or AnomalyDetector()

    def analyze(self, df: pd.DataFrame) -> TrafficReport:
        bytes_arr = df["bytes"].fillna(0).to_numpy(dtype=float)

        report = TrafficReport(
            total_requests = len(df),
            unique_ips     = df["ip"].nunique() if "ip" in df.columns else 0,
            error_rate_pct = round(
                df["status"].ge(400).sum() / max(len(df), 1) * 100, 2
            ) if "status" in df.columns else 0.0,
            top_paths  = df["path"].value_counts().head(5)  if "path"   in df.columns else pd.Series(dtype=int),
            top_ips    = df["ip"].value_counts().head(5)    if "ip"     in df.columns else pd.Series(dtype=int),
            status_dist= df["status"].value_counts()        if "status" in df.columns else pd.Series(dtype=int),
            bytes_stats= {
                "mean"   : round(float(np.nanmean(bytes_arr)),  2),
                "median" : round(float(np.nanmedian(bytes_arr)), 2),
                "std"    : round(float(np.nanstd(bytes_arr)),   2),
                "p95"    : round(float(np.nanpercentile(bytes_arr, 95)), 2),
                "max"    : round(float(np.nanmax(bytes_arr)),   2),
            },
            anomalies  = self.detector.detect(df),
        )
        return report

    def print_report(self, report: TrafficReport) -> None:
        sep = "─" * 50
        print(f"\n{'═'*50}")
        print("  LOG ANALYSIS REPORT")
        print(f"{'═'*50}")
        print(f"  Total Requests : {report.total_requests:,}")
        print(f"  Unique IPs     : {report.unique_ips:,}")
        print(f"  Error Rate     : {report.error_rate_pct}%")
        print(f"\n{sep}")
        print("  BYTE TRANSFER STATS (NumPy)")
        print(sep)
        for k, v in report.bytes_stats.items():
            print(f"  {k:<8} : {v:>12,.2f} bytes")
        print(f"\n{sep}")
        print("  TOP IPs")
        print(sep)
        print(report.top_ips.to_string())
        print(f"\n{sep}")
        print("  STATUS CODE DISTRIBUTION")
        print(sep)
        print(report.status_dist.to_string())
        print(f"\n{sep}")
        print(f"  ANOMALIES DETECTED: {len(report.anomalies)}")
        print(sep)
        for a in report.anomalies[:10]:
            tag = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢"}.get(a.severity,"⚪")
            print(f"  {tag} [{a.severity.upper():<8}] IP={a.ip:<15} score={a.score:.3f}  → {a.reason}")
        print(f"{'═'*50}\n")


# ──────────────────────────────────────────────
# 4. DEMO
# ──────────────────────────────────────────────

if __name__ == "__main__":
    from log_parser import LogParser, SAMPLE_LOGS

    df = LogParser("apache_common").load_string(SAMPLE_LOGS).parse()
    analyzer = TrafficAnalyzer()
    report   = analyzer.analyze(df)
    analyzer.print_report(report)
