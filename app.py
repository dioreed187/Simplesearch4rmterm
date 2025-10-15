from __future__ import annotations

import csv
import json
import os
from datetime import date, datetime
from pathlib import Path
import sqlite3
from typing import Iterable

from flask import Flask, render_template, request, redirect, url_for, flash, send_file

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "local_data"
EXPORTS_DIR = BASE_DIR / "exports"
DB_PATH = DATA_DIR / "cases.db"


def ensure_directories() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_db_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_no TEXT NOT NULL UNIQUE,
                investigator TEXT NOT NULL,
                case_date TEXT NOT NULL
            )
            """
        )
        conn.commit()


app = Flask(__name__)
# Local-only app; not sensitive, used for flashing messages.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "local-dev-secret")


@app.route("/")
def root() -> str:
    return redirect(url_for("list_cases"))


@app.route("/cases", methods=["GET"])
def list_cases() -> str:
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT id, case_no, investigator, case_date FROM cases ORDER BY case_date DESC, id DESC"
        ).fetchall()
    return render_template("cases_list.html", cases=rows)


@app.route("/cases/new", methods=["GET"])
def new_case_form() -> str:
    today = date.today().isoformat()
    return render_template("new_case.html", default_date=today)


@app.route("/cases", methods=["POST"])
def create_case():
    case_no = (request.form.get("case_no") or "").strip()
    investigator = (request.form.get("investigator") or "").strip()
    case_date = (request.form.get("date") or "").strip()

    error_messages: list[str] = []

    if not case_no:
        error_messages.append("Case No is required")
    if not investigator:
        error_messages.append("Investigator is required")
    if not case_date:
        error_messages.append("Date is required")
    else:
        # Validate ISO date (YYYY-MM-DD)
        try:
            datetime.strptime(case_date, "%Y-%m-%d")
        except ValueError:
            error_messages.append("Date must be in YYYY-MM-DD format")

    if error_messages:
        for msg in error_messages:
            flash(msg, category="error")
        return redirect(url_for("new_case_form"))

    try:
        with get_db_connection() as conn:
            conn.execute(
                "INSERT INTO cases (case_no, investigator, case_date) VALUES (?, ?, ?)",
                (case_no, investigator, case_date),
            )
            conn.commit()
        flash("Case created", category="success")
        return redirect(url_for("list_cases"))
    except sqlite3.IntegrityError:
        flash("Case No must be unique", category="error")
        return redirect(url_for("new_case_form"))


@app.route("/export.csv", methods=["GET"])
def export_csv():
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"cases-{timestamp}.csv"
    export_path = EXPORTS_DIR / filename

    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT case_no, investigator, case_date FROM cases ORDER BY case_date DESC, id DESC"
        ).fetchall()

    fieldnames = ["case_no", "investigator", "case_date"]
    with export_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow({
                "case_no": r["case_no"],
                "investigator": r["investigator"],
                "case_date": r["case_date"],
            })

    # Also return the file for immediate download
    return send_file(export_path, as_attachment=True, download_name=filename)


@app.route("/export.json", methods=["GET"])
def export_json():
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"cases-{timestamp}.json"
    export_path = EXPORTS_DIR / filename

    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT case_no, investigator, case_date FROM cases ORDER BY case_date DESC, id DESC"
        ).fetchall()

    payload = [
        {
            "case_no": r["case_no"],
            "investigator": r["investigator"],
            "case_date": r["case_date"],
        }
        for r in rows
    ]

    export_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return send_file(export_path, as_attachment=True, download_name=filename)


@app.route("/healthz")
def healthz() -> tuple[str, int]:
    return "ok", 200


if __name__ == "__main__":
    ensure_directories()
    init_db()
    # Bind to localhost only; no external exposure by default
    app.run(host="127.0.0.1", port=5000, debug=True)
