import csv
from datetime import datetime
from pathlib import Path

LOG_FILE = Path("logs/scan_logs.csv")

def log_scan(result: dict):
    LOG_FILE.parent.mkdir(exist_ok=True)
    file_exists = LOG_FILE.exists()

    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow([
                "timestamp",
                "url",
                "label",
                "risk_score",
                "reasons"
            ])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            result.get("url"),
            result.get("label"),
            result.get("risk_score"),
            "; ".join(result.get("reasons", []))
        ])
