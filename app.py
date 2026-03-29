import json
import os
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from database import ScanRecord, db
from realtime.decision_engine import decide_phishing

BASE_DIR = Path(__file__).resolve().parent


def get_database_uri() -> str:
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        return database_url.replace("postgres://", "postgresql://", 1)

    sqlite_path = os.getenv("SQLITE_PATH")
    if sqlite_path:
        return f"sqlite:///{sqlite_path}"

    if os.getenv("VERCEL"):
        return "sqlite:////tmp/phishing_scans.db"

    return f"sqlite:///{BASE_DIR / 'instance' / 'phishing_scans.db'}"


def ensure_sqlite_directory(database_uri: str) -> None:
    if not database_uri.startswith("sqlite:///"):
        return

    sqlite_path = Path(database_uri.removeprefix("sqlite:///"))
    sqlite_path.parent.mkdir(parents=True, exist_ok=True)


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = get_database_uri()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

ensure_sqlite_directory(app.config["SQLALCHEMY_DATABASE_URI"])
db.init_app(app)

with app.app_context():
    db.create_all()


@app.route("/")
def home():
    """Home page with carousel"""
    return render_template("home_page.html")


@app.route("/scanner", methods=["GET", "POST"])
def scanner():
    result = None
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            result = decide_phishing(url)

            # Save to database
            reasons_json = json.dumps(result.get("reasons", []))
            scan_record = ScanRecord(
                url=url,
                result="PHISHING" if result.get("is_phishing", False) else "LEGITIMATE",
                risk_score=result.get("risk_score", 0),
                confidence=result.get("confidence", 0),
                reasons=reasons_json,
            )
            db.session.add(scan_record)
            db.session.commit()

    # Get last 10 scans
    history = ScanRecord.query.order_by(ScanRecord.timestamp.desc()).limit(10).all()
    history = [record.to_dict() for record in history]

    stats = get_stats()

    return render_template("index.html", result=result, history=history, stats=stats)


def get_stats():
    """Get scanning statistics"""
    total = ScanRecord.query.count()
    if total == 0:
        return {
            "total_scans": 0,
            "phishing_count": 0,
            "legitimate_count": 0,
            "detection_rate": 0,
            "today_scans": 0,
            "today_phishing": 0,
        }

    phishing = ScanRecord.query.filter_by(result="PHISHING").count()
    legitimate = ScanRecord.query.filter_by(result="LEGITIMATE").count()

    # Today's stats - use UTC time to match database timestamp
    from datetime import datetime, timedelta

    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)

    today_scans = ScanRecord.query.filter(
        ScanRecord.timestamp >= today_start,
        ScanRecord.timestamp < today_end,
    ).count()
    today_phishing = ScanRecord.query.filter(
        ScanRecord.timestamp >= today_start,
        ScanRecord.timestamp < today_end,
        ScanRecord.result == "PHISHING",
    ).count()

    return {
        "total_scans": total,
        "phishing_count": phishing,
        "legitimate_count": legitimate,
        "detection_rate": round((phishing / total) * 100, 1),
        "today_scans": today_scans,
        "today_phishing": today_phishing,
    }


@app.route("/api/stats")
def api_stats():
    """API endpoint for statistics"""
    return jsonify(get_stats())


@app.route("/api/history")
def api_history():
    """API endpoint for scan history"""
    limit = request.args.get("limit", 50, type=int)
    records = ScanRecord.query.order_by(ScanRecord.timestamp.desc()).limit(limit).all()
    return jsonify([record.to_dict() for record in records])


@app.route("/health")
def health():
    """Lightweight health check for deployment platforms."""
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True)
