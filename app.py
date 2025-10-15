from __future__ import annotations

import csv
import json
import os
import re
import hashlib
import mimetypes
from datetime import date, datetime
from pathlib import Path
import sqlite3
from typing import Iterable, Optional, Dict, Any, List, Tuple

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_file,
    abort,
)
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "local_data"
EXPORTS_DIR = BASE_DIR / "exports"
EVIDENCE_BASE_DIR = DATA_DIR / "cases"
DB_PATH = DATA_DIR / "cases.db"

# Limit uploads (bytes). Adjust as needed
MAX_CONTENT_LENGTH = int(os.environ.get("ABI_MAX_UPLOAD_BYTES", 100 * 1024 * 1024))  # 100 MB


def ensure_directories() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_BASE_DIR.mkdir(parents=True, exist_ok=True)


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return bool(row)


def init_db() -> None:
    with get_db_connection() as conn:
        # Cases
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
        # Evidence
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                original_filename TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                mime_type TEXT,
                size_bytes INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        # Analysis results (JSON per type)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
                analysis_type TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        # Extracted IOCs
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                context_excerpt TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        # Extracted textual content per evidence
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence_texts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
                content TEXT NOT NULL
            )
            """
        )
        # Optional FTS5 index (if available)
        try:
            conn.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS evidence_text_fts
                USING fts5(content, evidence_id UNINDEXED, content='evidence_texts', content_rowid='id')
                """
            )
        except sqlite3.OperationalError:
            # FTS5 not supported in this SQLite build; that's okay.
            pass
        conn.commit()


app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
# Local-only app; not sensitive, used for flashing messages.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "local-dev-secret")


# -----------------------
# Utility: File handling
# -----------------------

def _detect_mime_type(filename: str) -> Optional[str]:
    mt, _ = mimetypes.guess_type(filename)
    return mt


def _case_dir(case_id: int) -> Path:
    p = EVIDENCE_BASE_DIR / str(case_id)
    p.mkdir(parents=True, exist_ok=True)
    return p


# -----------------------
# Utility: Analysis helpers
# -----------------------

def compute_hashes(file_path: Path) -> Dict[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with file_path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        'md5': md5.hexdigest(),
        'sha1': sha1.hexdigest(),
        'sha256': sha256.hexdigest(),
    }


def extract_exif_if_image(file_path: Path) -> Optional[Dict[str, Any]]:
    # Lazy import to avoid hard dependency at startup
    try:
        from PIL import Image, ExifTags  # type: ignore
    except Exception:
        return None
    try:
        with Image.open(file_path) as img:
            exif_data = getattr(img, "_getexif", lambda: None)()
            if not exif_data:
                return None
            tag_map = {ExifTags.TAGS.get(k, str(k)): v for k, v in exif_data.items()}
            # Convert bytes to str where feasible
            cleaned: Dict[str, Any] = {}
            for k, v in tag_map.items():
                if isinstance(v, bytes):
                    try:
                        cleaned[k] = v.decode('utf-8', errors='replace')
                    except Exception:
                        cleaned[k] = str(v)
                else:
                    cleaned[k] = v
            return cleaned
    except Exception:
        return None


def _read_text_guess_encoding(file_path: Path, limit_bytes: int = 5_000_000) -> Optional[str]:
    # Try chardet if available
    try:
        import chardet  # type: ignore
    except Exception:
        chardet = None  # type: ignore
    b = file_path.read_bytes()[:limit_bytes]
    encoding = 'utf-8'
    if chardet is not None:
        try:
            det = chardet.detect(b)
            if det and det.get('encoding'):
                encoding = det['encoding']  # type: ignore
        except Exception:
            pass
    try:
        return b.decode(encoding or 'utf-8', errors='replace')
    except Exception:
        try:
            return b.decode('utf-8', errors='replace')
        except Exception:
            return None


def extract_text_from_file(file_path: Path, mime_type: Optional[str]) -> Tuple[Optional[str], str]:
    """
    Returns (text, method) where method indicates extractor used.
    """
    suffix = file_path.suffix.lower()
    # PDF
    if suffix == '.pdf' or (mime_type and 'pdf' in mime_type):
        try:
            from pdfminer.high_level import extract_text  # type: ignore
            text = extract_text(str(file_path))
            return (text or ''), 'pdfminer'
        except Exception:
            return None, 'pdfminer_failed'
    # DOCX
    if suffix == '.docx':
        try:
            import docx  # type: ignore
            d = docx.Document(str(file_path))
            text = "\n".join(p.text for p in d.paragraphs)
            return (text or ''), 'python-docx'
        except Exception:
            return None, 'docx_failed'
    # HTML
    if suffix in ('.html', '.htm') or (mime_type and 'html' in mime_type):
        try:
            from bs4 import BeautifulSoup  # type: ignore
            html = file_path.read_text(encoding='utf-8', errors='ignore')
            soup = BeautifulSoup(html, 'lxml') if 'lxml' else BeautifulSoup(html, 'html.parser')
            # Remove script/style
            for tag in soup(['script', 'style']):
                tag.decompose()
            text = soup.get_text(separator='\n')
            return (text or ''), 'beautifulsoup'
        except Exception:
            return None, 'html_failed'
    # Plain text-like
    if suffix in ('.txt', '.log', '.json', '.csv', '.md', '.ini', '.cfg', '.conf') or (mime_type and mime_type.startswith('text/')):
        text = _read_text_guess_encoding(file_path)
        return (text or '' if text else None), 'text'
    return None, 'unknown'


def extract_strings(file_path: Path, min_length: int = 4, limit_bytes: int = 20_000_000) -> Dict[str, Any]:
    data = file_path.read_bytes()[:limit_bytes]
    # ASCII strings
    ascii_pat = re.compile(rb"[ -~]{%d,}" % min_length)
    ascii_strings = [m.group().decode('utf-8', errors='replace') for m in ascii_pat.finditer(data)]
    # UTF-16LE (printable ASCII chars with null bytes)
    try:
        uni = data.decode('utf-16le', errors='ignore')
        uni_candidates = [s for s in re.findall(r"[\x20-\x7E]{%d,}" % min_length, uni)]
    except Exception:
        uni_candidates = []
    return {
        'ascii': ascii_strings[:5000],  # cap to avoid huge payloads
        'utf16le': uni_candidates[:5000],
        'total_ascii': len(ascii_strings),
        'total_utf16le': len(uni_candidates),
    }


# IOC extraction
IOC_PATTERNS = {
    'ipv4': re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    'email': re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,24}\b"),
    'md5': re.compile(r"\b[a-fA-F0-9]{32}\b"),
    'sha1': re.compile(r"\b[a-fA-F0-9]{40}\b"),
    'sha256': re.compile(r"\b[a-fA-F0-9]{64}\b"),
    'url': re.compile(r"\bhttps?://[\w\-\.:@%/\+#?=&~;,]+", re.IGNORECASE),
    'domain': re.compile(r"\b(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,24}\b"),
}


def extract_iocs_from_text(text: str, context_window: int = 60) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    for ioc_type, pattern in IOC_PATTERNS.items():
        for m in pattern.finditer(text):
            start, end = m.span()
            left = max(0, start - context_window)
            right = min(len(text), end + context_window)
            excerpt = text[left:right].replace('\n', ' ')
            results.append({
                'ioc_type': ioc_type,
                'ioc_value': m.group(0),
                'context_excerpt': excerpt,
            })
    return results


def _fts_available(conn: sqlite3.Connection) -> bool:
    try:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='evidence_text_fts'"
        ).fetchone()
        return bool(row)
    except Exception:
        return False


def run_analyses(evidence_id: int, file_path: Path, mime_type: Optional[str]) -> None:
    now = datetime.utcnow().isoformat()
    analyses_to_insert: List[Tuple[str, Dict[str, Any]]] = []

    # Hashes
    hashes = compute_hashes(file_path)
    analyses_to_insert.append(("hashes", hashes))

    # EXIF (if image)
    exif = extract_exif_if_image(file_path)
    if exif:
        analyses_to_insert.append(("exif", exif))

    # Text extraction
    text, method = extract_text_from_file(file_path, mime_type)
    if text:
        analyses_to_insert.append(("text_extract", {"method": method, "length": len(text)}))

    # Strings
    strings_info = extract_strings(file_path)
    analyses_to_insert.append(("strings", {
        "ascii_count": strings_info["total_ascii"],
        "utf16le_count": strings_info["total_utf16le"],
    }))

    # IOC extraction from any available textual material
    iocs: List[Dict[str, str]] = []
    combined_text_sources: List[str] = []
    if text:
        combined_text_sources.append(text)
    # Use a small sample of ASCII strings to hunt additional IOCs
    ascii_sample = "\n".join(strings_info.get('ascii', [])[:1000])
    if ascii_sample:
        combined_text_sources.append(ascii_sample)
    if combined_text_sources:
        iocs = extract_iocs_from_text("\n".join(combined_text_sources))

    # Persist results
    with get_db_connection() as conn:
        for analysis_type, payload in analyses_to_insert:
            conn.execute(
                "INSERT INTO analysis (evidence_id, analysis_type, result_json, created_at) VALUES (?, ?, ?, ?)",
                (evidence_id, analysis_type, json.dumps(payload, ensure_ascii=False), now),
            )
        # Save text content and FTS entry
        if text:
            cur = conn.execute(
                "INSERT INTO evidence_texts (evidence_id, content) VALUES (?, ?)",
                (evidence_id, text),
            )
            # If FTS exists, insert row directly
            if _fts_available(conn):
                rowid = cur.lastrowid
                conn.execute(
                    "INSERT INTO evidence_text_fts(rowid, content, evidence_id) VALUES (?, ?, ?)",
                    (rowid, text, evidence_id),
                )
        # Save IOCs
        for item in iocs:
            conn.execute(
                "INSERT INTO iocs (evidence_id, ioc_type, ioc_value, context_excerpt, created_at) VALUES (?, ?, ?, ?, ?)",
                (
                    evidence_id,
                    item["ioc_type"],
                    item["ioc_value"],
                    item.get("context_excerpt"),
                    now,
                ),
            )
        conn.commit()


# -----------------------
# Routes: Cases and Evidence
# -----------------------

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


@app.route('/cases/<int:case_id>', methods=['GET'])
def case_detail(case_id: int):
    with get_db_connection() as conn:
        case = conn.execute(
            "SELECT id, case_no, investigator, case_date FROM cases WHERE id=?", (case_id,)
        ).fetchone()
        if not case:
            abort(404)
        evidences = conn.execute(
            """
            SELECT id, original_filename, mime_type, size_bytes, created_at
            FROM evidence WHERE case_id=? ORDER BY created_at DESC, id DESC
            """,
            (case_id,),
        ).fetchall()
    return render_template('case_detail.html', case=case, evidences=evidences)


@app.route('/cases/<int:case_id>/evidence', methods=['POST'])
def upload_evidence(case_id: int):
    # Ensure case exists
    with get_db_connection() as conn:
        case = conn.execute("SELECT id FROM cases WHERE id=?", (case_id,)).fetchone()
        if not case:
            abort(404)

    file = request.files.get('file')
    if not file or file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('case_detail', case_id=case_id))

    # Save file
    filename = secure_filename(file.filename)
    if not filename:
        flash('Invalid filename', 'error')
        return redirect(url_for('case_detail', case_id=case_id))

    stored_dir = _case_dir(case_id)
    timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    stored_name = f"{timestamp}_{filename}"
    stored_path = stored_dir / stored_name
    file.save(str(stored_path))

    mime_type = _detect_mime_type(filename)
    size_bytes = stored_path.stat().st_size

    with get_db_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO evidence (case_id, original_filename, stored_path, mime_type, size_bytes, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                filename,
                str(stored_path),
                mime_type,
                size_bytes,
                datetime.utcnow().isoformat(),
            ),
        )
        evidence_id = cur.lastrowid
        conn.commit()

    # Run analyses synchronously (local, no external services)
    try:
        run_analyses(evidence_id, stored_path, mime_type)
        flash('Evidence uploaded and analyzed', 'success')
    except Exception as ex:
        flash(f'Evidence uploaded but analysis failed: {ex}', 'error')

    return redirect(url_for('evidence_detail', evidence_id=evidence_id))


@app.route('/evidence/<int:evidence_id>', methods=['GET'])
def evidence_detail(evidence_id: int):
    with get_db_connection() as conn:
        ev = conn.execute(
            """
            SELECT e.id, e.case_id, e.original_filename, e.stored_path, e.mime_type, e.size_bytes, e.created_at,
                   c.case_no
            FROM evidence e JOIN cases c ON e.case_id = c.id
            WHERE e.id=?
            """,
            (evidence_id,),
        ).fetchone()
        if not ev:
            abort(404)
        analyses = conn.execute(
            "SELECT analysis_type, result_json, created_at FROM analysis WHERE evidence_id=? ORDER BY id",
            (evidence_id,),
        ).fetchall()
        iocs = conn.execute(
            "SELECT ioc_type, ioc_value, context_excerpt FROM iocs WHERE evidence_id=? ORDER BY id",
            (evidence_id,),
        ).fetchall()
        text_row = conn.execute(
            "SELECT content FROM evidence_texts WHERE evidence_id=? ORDER BY id LIMIT 1",
            (evidence_id,),
        ).fetchone()
    text_preview = None
    if text_row:
        content = text_row[0]
        text_preview = content[:4000]
    # Parse analysis JSON
    parsed_analyses = [
        {
            'analysis_type': a['analysis_type'],
            'created_at': a['created_at'],
            'payload': json.loads(a['result_json'] or '{}')
        }
        for a in analyses
    ]
    return render_template('evidence_detail.html', ev=ev, analyses=parsed_analyses, iocs=iocs, text_preview=text_preview)


@app.route('/evidence/<int:evidence_id>/download', methods=['GET'])
def evidence_download(evidence_id: int):
    with get_db_connection() as conn:
        ev = conn.execute(
            "SELECT stored_path, original_filename FROM evidence WHERE id=?",
            (evidence_id,),
        ).fetchone()
    if not ev:
        abort(404)
    path = Path(ev['stored_path'])
    if not path.exists():
        abort(404)
    return send_file(path, as_attachment=True, download_name=ev['original_filename'])


# -----------------------
# Exports
# -----------------------

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


@app.route('/export/evidence.csv', methods=['GET'])
def export_evidence_csv():
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"evidence-{timestamp}.csv"
    export_path = EXPORTS_DIR / filename
    with get_db_connection() as conn:
        rows = conn.execute(
            """
            SELECT e.id, e.case_id, c.case_no, e.original_filename, e.mime_type, e.size_bytes, e.created_at
            FROM evidence e JOIN cases c ON e.case_id=c.id
            ORDER BY e.created_at DESC, e.id DESC
            """
        ).fetchall()
    fieldnames = ["id", "case_id", "case_no", "original_filename", "mime_type", "size_bytes", "created_at"]
    with export_path.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r[k] for k in fieldnames})
    return send_file(export_path, as_attachment=True, download_name=filename)


@app.route('/export/iocs.csv', methods=['GET'])
def export_iocs_csv():
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"iocs-{timestamp}.csv"
    export_path = EXPORTS_DIR / filename
    with get_db_connection() as conn:
        rows = conn.execute(
            """
            SELECT i.ioc_type, i.ioc_value, i.context_excerpt, i.created_at, e.id AS evidence_id, c.case_no
            FROM iocs i
            JOIN evidence e ON i.evidence_id = e.id
            JOIN cases c ON e.case_id = c.id
            ORDER BY i.created_at DESC, i.id DESC
            """
        ).fetchall()
    fieldnames = ["ioc_type", "ioc_value", "context_excerpt", "created_at", "evidence_id", "case_no"]
    with export_path.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r[k] for k in fieldnames})
    return send_file(export_path, as_attachment=True, download_name=filename)


# -----------------------
# Search
# -----------------------

@app.route('/search', methods=['GET'])
def search():
    q = (request.args.get('q') or '').strip()
    results: List[sqlite3.Row] = []
    using_fts = False
    if q:
        with get_db_connection() as conn:
            if _fts_available(conn):
                using_fts = True
                results = conn.execute(
                    """
                    SELECT e.id AS evidence_id, e.original_filename, c.case_no, snippet(evidence_text_fts) AS snippet
                    FROM evidence_text_fts
                    JOIN evidence_texts t ON t.id = evidence_text_fts.rowid
                    JOIN evidence e ON t.evidence_id = e.id
                    JOIN cases c ON e.case_id = c.id
                    WHERE evidence_text_fts MATCH ?
                    LIMIT 200
                    """,
                    (q,),
                ).fetchall()
            else:
                like = f"%{q}%"
                results = conn.execute(
                    """
                    SELECT e.id AS evidence_id, e.original_filename, c.case_no, substr(t.content, 1, 300) AS snippet
                    FROM evidence_texts t
                    JOIN evidence e ON t.evidence_id = e.id
                    JOIN cases c ON e.case_id = c.id
                    WHERE t.content LIKE ?
                    LIMIT 200
                    """,
                    (like,),
                ).fetchall()
    return render_template('search.html', q=q, results=results, using_fts=using_fts)


# -----------------------
# Tools: IOC extractor (offline)
# -----------------------

@app.route('/tools/ioc', methods=['GET', 'POST'])
def tools_ioc():
    extracted: List[Dict[str, str]] = []
    input_text = ''
    if request.method == 'POST':
        input_text = (request.form.get('text') or '').strip()
        upload = request.files.get('file')
        if upload and upload.filename:
            # Try to read uploaded text file only
            tmp = Path(BASE_DIR) / f"tmp_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{secure_filename(upload.filename)}"
            upload.save(str(tmp))
            # Try text extraction as for evidence
            mime_type = _detect_mime_type(upload.filename)
            txt, _ = extract_text_from_file(tmp, mime_type)
            if txt:
                input_text += ("\n\n" + txt)
            tmp.unlink(missing_ok=True)
        if input_text:
            extracted = extract_iocs_from_text(input_text)
            flash(f"Extracted {len(extracted)} IOC(s)", 'success')
        else:
            flash('Provide text or upload a file', 'error')
    return render_template('tools_ioc.html', extracted=extracted, input_text=input_text)


@app.route("/healthz")
def healthz() -> tuple[str, int]:
    return "ok", 200


if __name__ == "__main__":
    ensure_directories()
    init_db()
    # Bind to localhost only; no external exposure by default
    app.run(host="127.0.0.1", port=5000, debug=True)
