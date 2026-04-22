"""
Scan results storage — SQLite backend for large-scale scanning.

Supports thousands of records with filtering, pagination, and export.
"""

import json
import hashlib
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

DB_DIR = Path.home() / ".guardian"
DB_FILE = DB_DIR / "scan_results.db"

_local = threading.local()


def _get_conn() -> sqlite3.Connection:
    """Thread-local SQLite connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        DB_DIR.mkdir(parents=True, exist_ok=True)
        _local.conn = sqlite3.connect(str(DB_FILE), check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _init_tables(_local.conn)
    return _local.conn


def _init_tables(conn: sqlite3.Connection):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS batch_scans (
            id              TEXT PRIMARY KEY,
            name            TEXT NOT NULL,
            source_path     TEXT DEFAULT '',
            status          TEXT DEFAULT 'running',
            total_skills    INTEGER DEFAULT 0,
            scanned         INTEGER DEFAULT 0,
            safe            INTEGER DEFAULT 0,
            unsafe          INTEGER DEFAULT 0,
            error           INTEGER DEFAULT 0,
            false_negatives INTEGER DEFAULT 0,
            latency_total   REAL DEFAULT 0,
            latency_avg     REAL DEFAULT 0,
            created_at      TEXT DEFAULT (datetime('now')),
            finished_at     TEXT
        );

        CREATE TABLE IF NOT EXISTS scan_results (
            id              TEXT PRIMARY KEY,
            skill_name      TEXT NOT NULL,
            skill_description TEXT DEFAULT '',
            verdict         TEXT NOT NULL,
            false_negative  INTEGER DEFAULT 0,
            scan_time       TEXT NOT NULL,
            source          TEXT DEFAULT '用户提交',

            -- Latency (seconds)
            latency_total   REAL DEFAULT 0,
            latency_static  REAL DEFAULT 0,
            latency_llm     REAL DEFAULT 0,
            latency_runtime REAL DEFAULT 0,
            latency_verify  REAL DEFAULT 0,

            -- Stage results (JSON)
            stages          TEXT DEFAULT '{}',
            capabilities    TEXT DEFAULT '[]',
            warnings        TEXT DEFAULT '[]',
            recommendations TEXT DEFAULT '[]',

            -- Searchable fields
            findings_count  INTEGER DEFAULT 0,
            max_severity    TEXT DEFAULT 'NONE',
            safety_confidence REAL,
            runtime_status  TEXT DEFAULT 'SKIPPED',
            blacklist_hits  INTEGER DEFAULT 0,
            blocks          INTEGER DEFAULT 0,

            batch_id        TEXT DEFAULT NULL,
            created_at      TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_batch_id ON scan_results(batch_id);
        CREATE INDEX IF NOT EXISTS idx_verdict ON scan_results(verdict);
        CREATE INDEX IF NOT EXISTS idx_scan_time ON scan_results(scan_time);
        CREATE INDEX IF NOT EXISTS idx_skill_name ON scan_results(skill_name);
        CREATE INDEX IF NOT EXISTS idx_false_negative ON scan_results(false_negative);
    """)
    conn.commit()

    # Add skill_hash column (migration for existing DBs)
    try:
        conn.execute("ALTER TABLE scan_results ADD COLUMN skill_hash TEXT DEFAULT ''")
        conn.commit()
    except Exception:
        pass  # Column already exists
    conn.execute("CREATE INDEX IF NOT EXISTS idx_skill_hash ON scan_results(skill_hash)")
    conn.commit()
    # Add recommendations_en column (migration for bilingual reports)
    try:
        conn.execute("ALTER TABLE scan_results ADD COLUMN recommendations_en TEXT DEFAULT '[]'")
        conn.commit()
    except Exception:
        pass  # Column already exists


def compute_skill_hash(skill_path: str) -> str:
    """SHA256 of all files in a skill directory, truncated to 32 hex chars."""
    h = hashlib.sha256()
    skill_dir = Path(skill_path)
    if not skill_dir.exists():
        return ""
    for fpath in sorted(skill_dir.rglob("*")):
        if fpath.is_file() and "__pycache__" not in str(fpath):
            try:
                h.update(fpath.read_bytes())
            except Exception:
                pass
    return h.hexdigest()[:32]


def find_by_skill_hash(skill_hash: str, lang: str = "en") -> Optional[dict]:
    """Return latest scan record with matching skill_hash; None if no usable cache."""
    if not skill_hash:
        return None
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM scan_results WHERE skill_hash = ? ORDER BY scan_time DESC LIMIT 1",
        (skill_hash,)
    ).fetchone()
    if not row:
        return None
    record = dict(row)
    # Bilingual records (non-empty recommendations_en) serve both zh and en.
    # Legacy single-lang records fall back to source-based language inference.
    recs_en_raw = record.get("recommendations_en") or ""
    is_bilingual = bool(recs_en_raw) and recs_en_raw not in ("", "[]")
    if not is_bilingual:
        source = record.get("source", "") or ""
        is_zh_record = any("一" < c < "鿿" for c in source)
        if (lang == "en" and is_zh_record) or (lang == "zh" and not is_zh_record):
            return None
    for field in ("stages", "capabilities", "warnings", "recommendations", "recommendations_en"):
        try:
            record[field] = json.loads(record[field])
        except (json.JSONDecodeError, TypeError):
            pass
    record["false_negative"] = bool(record["false_negative"])
    record["latency"] = {
        "total": record.pop("latency_total", 0),
        "static": record.pop("latency_static", 0),
        "llm": record.pop("latency_llm", 0),
        "runtime": record.pop("latency_runtime", 0),
        "verify": record.pop("latency_verify", 0),
    }
    return record


def save_scan(report: dict, skill_hash: str = "") -> str:
    """Save a scan report to the database. Returns the record ID."""
    conn = _get_conn()

    scan_id = hashlib.md5(
        f"{report.get('skill_name','')}{report.get('scan_time','')}".encode()
    ).hexdigest()[:16]

    stages = report.get("stages", {})
    latency = report.get("latency", {})

    batch_id = report.get("batch_id")

    conn.execute("""
        INSERT OR REPLACE INTO scan_results (
            id, skill_name, skill_description, verdict, false_negative,
            scan_time, source, batch_id,
            latency_total, latency_static, latency_llm, latency_runtime, latency_verify,
            stages, capabilities, warnings, recommendations, recommendations_en,
            findings_count, max_severity, safety_confidence,
            runtime_status, blacklist_hits, blocks, skill_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        report.get("skill_name", "unknown"),
        report.get("skill_description", ""),
        report.get("verdict", "UNKNOWN"),
        1 if report.get("false_negative") else 0,
        report.get("scan_time", datetime.now().strftime("%Y/%m/%d %H:%M:%S")),
        report.get("source", "用户提交"),
        batch_id,
        latency.get("total", 0),
        latency.get("static", 0),
        latency.get("llm", 0),
        latency.get("runtime", 0),
        latency.get("verify", 0),
        json.dumps(stages, ensure_ascii=False),
        json.dumps(report.get("capabilities", []), ensure_ascii=False),
        json.dumps(report.get("warnings", []), ensure_ascii=False),
        json.dumps(report.get("recommendations", []), ensure_ascii=False),
        json.dumps(report.get("recommendations_en", []), ensure_ascii=False),
        stages.get("static", {}).get("findings", 0),
        stages.get("static", {}).get("severity", "NONE"),
        stages.get("llm", {}).get("confidence"),
        stages.get("runtime", {}).get("status", "SKIPPED"),
        stages.get("runtime", {}).get("blacklist_hits", 0),
        stages.get("runtime", {}).get("blocks", 0),
        skill_hash,
    ))
    conn.commit()
    return scan_id


def get_history(
    limit: int = 50,
    offset: int = 0,
    verdict: Optional[str] = None,
    skill_name: Optional[str] = None,
    false_negative_only: bool = False,
) -> dict:
    """Query scan history with filtering and pagination."""
    conn = _get_conn()

    where_clauses = []
    params = []

    if verdict:
        where_clauses.append("verdict = ?")
        params.append(verdict)
    if skill_name:
        where_clauses.append("skill_name LIKE ?")
        params.append(f"%{skill_name}%")
    if false_negative_only:
        where_clauses.append("false_negative = 1")

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    # Total count
    count_row = conn.execute(
        f"SELECT COUNT(*) as cnt FROM scan_results {where_sql}", params
    ).fetchone()
    total = count_row["cnt"]

    # Fetch page
    rows = conn.execute(
        f"""SELECT * FROM scan_results {where_sql}
            ORDER BY scan_time DESC LIMIT ? OFFSET ?""",
        params + [limit, offset]
    ).fetchall()

    records = []
    for row in rows:
        record = dict(row)
        # Parse JSON fields back
        for field in ("stages", "capabilities", "warnings", "recommendations", "recommendations_en"):
            try:
                record[field] = json.loads(record[field])
            except (json.JSONDecodeError, TypeError):
                pass
        record["false_negative"] = bool(record["false_negative"])
        # Add latency summary
        record["latency"] = {
            "total": record.pop("latency_total", 0),
            "static": record.pop("latency_static", 0),
            "llm": record.pop("latency_llm", 0),
            "runtime": record.pop("latency_runtime", 0),
            "verify": record.pop("latency_verify", 0),
        }
        records.append(record)

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "records": records,
    }


def get_stats() -> dict:
    """Get aggregate statistics across all scans."""
    conn = _get_conn()

    total = conn.execute("SELECT COUNT(*) as cnt FROM scan_results").fetchone()["cnt"]
    if total == 0:
        return {"total": 0}

    verdicts = {}
    for row in conn.execute("SELECT verdict, COUNT(*) as cnt FROM scan_results GROUP BY verdict"):
        verdicts[row["verdict"]] = row["cnt"]

    fn_count = conn.execute("SELECT COUNT(*) as cnt FROM scan_results WHERE false_negative=1").fetchone()["cnt"]

    avg_latency = conn.execute("""
        SELECT
            AVG(latency_total) as avg_total,
            AVG(latency_static) as avg_static,
            AVG(latency_llm) as avg_llm,
            AVG(latency_runtime) as avg_runtime
        FROM scan_results
    """).fetchone()

    return {
        "total": total,
        "verdicts": verdicts,
        "false_negatives": fn_count,
        "avg_latency": {
            "total": round(avg_latency["avg_total"] or 0, 2),
            "static": round(avg_latency["avg_static"] or 0, 2),
            "llm": round(avg_latency["avg_llm"] or 0, 2),
            "runtime": round(avg_latency["avg_runtime"] or 0, 2),
        },
    }


def export_csv(filepath: str, verdict: Optional[str] = None):
    """Export scan results to CSV."""
    import csv
    conn = _get_conn()

    where = f"WHERE verdict = '{verdict}'" if verdict else ""
    rows = conn.execute(
        f"SELECT id, skill_name, verdict, false_negative, scan_time, "
        f"findings_count, max_severity, safety_confidence, runtime_status, "
        f"blacklist_hits, blocks, latency_total, latency_static, latency_llm, "
        f"latency_runtime FROM scan_results {where} ORDER BY scan_time DESC"
    ).fetchall()

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "id", "skill_name", "verdict", "false_negative", "scan_time",
            "findings_count", "max_severity", "safety_confidence", "runtime_status",
            "blacklist_hits", "blocks", "latency_total", "latency_static",
            "latency_llm", "latency_runtime",
        ])
        for row in rows:
            writer.writerow(list(row))

    return len(rows)


# ── Migration: import old scan_history.json ──

def migrate_from_json(json_path: str):
    """One-time migration from scan_history.json to SQLite."""
    p = Path(json_path)
    if not p.exists():
        return 0

    try:
        data = json.loads(p.read_text())
    except Exception:
        return 0

    count = 0
    for entry in data:
        # Add empty latency if missing
        if "latency" not in entry:
            entry["latency"] = {}
        save_scan(entry)
        count += 1

    return count


# ── Batch scan operations ──

def create_batch(batch_id: str, name: str, source_path: str, total_skills: int):
    conn = _get_conn()
    conn.execute("""
        INSERT OR REPLACE INTO batch_scans (id, name, source_path, status, total_skills)
        VALUES (?, ?, ?, 'running', ?)
    """, (batch_id, name, source_path, total_skills))
    conn.commit()


def update_batch_progress(batch_id: str, report: dict):
    """Called after each skill scan completes. Updates batch counters."""
    conn = _get_conn()
    verdict = report.get("verdict", "UNKNOWN")
    fn = 1 if report.get("false_negative") else 0
    lat = report.get("latency", {}).get("total", 0)

    safe_inc = 1 if verdict in ("PASSED", "SAFE") else 0
    unsafe_inc = 1 if verdict in ("BLOCKED", "CAPABILITY_RISK", "CONTENT_RISK", "UNSAFE") else 0
    error_inc = 1 if verdict in ("ERROR", "TIMEOUT") else 0

    conn.execute("""
        UPDATE batch_scans SET
            scanned = scanned + 1,
            safe = safe + ?,
            unsafe = unsafe + ?,
            error = error + ?,
            false_negatives = false_negatives + ?,
            latency_total = latency_total + ?
        WHERE id = ?
    """, (safe_inc, unsafe_inc, error_inc, fn, lat, batch_id))
    conn.commit()


def finish_batch(batch_id: str):
    conn = _get_conn()
    row = conn.execute("SELECT scanned, latency_total FROM batch_scans WHERE id=?", (batch_id,)).fetchone()
    avg = round(row["latency_total"] / max(row["scanned"], 1), 2)
    conn.execute("""
        UPDATE batch_scans SET status='done', latency_avg=?, finished_at=datetime('now')
        WHERE id=?
    """, (avg, batch_id))
    conn.commit()


def get_batch(batch_id: str) -> Optional[dict]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM batch_scans WHERE id=?", (batch_id,)).fetchone()
    if not row:
        return None
    return dict(row)


def get_batch_skills(batch_id: str, limit: int = 200, offset: int = 0) -> dict:
    """Get all skill scan results for a batch."""
    conn = _get_conn()
    total = conn.execute(
        "SELECT COUNT(*) as cnt FROM scan_results WHERE batch_id=?", (batch_id,)
    ).fetchone()["cnt"]

    rows = conn.execute("""
        SELECT id, skill_name, verdict, false_negative, scan_time,
               findings_count, max_severity, safety_confidence, runtime_status,
               latency_total, latency_static, latency_llm, latency_runtime,
               warnings, recommendations
        FROM scan_results WHERE batch_id=?
        ORDER BY
            CASE verdict
                WHEN 'BLOCKED' THEN 0
                WHEN 'CAPABILITY_RISK' THEN 1
                WHEN 'CONTENT_RISK' THEN 2
                WHEN 'UNSAFE' THEN 3
                WHEN 'ALERT' THEN 4
                WHEN 'ERROR' THEN 5
                WHEN 'TIMEOUT' THEN 6
                WHEN 'PASSED' THEN 7
                ELSE 8
            END,
            skill_name
        LIMIT ? OFFSET ?
    """, (batch_id, limit, offset)).fetchall()

    records = []
    for row in rows:
        r = dict(row)
        r["false_negative"] = bool(r["false_negative"])
        for f in ("warnings", "recommendations", "recommendations_en"):
            try:
                r[f] = json.loads(r[f])
            except (json.JSONDecodeError, TypeError):
                pass
        r["latency"] = {
            "total": r.pop("latency_total", 0),
            "static": r.pop("latency_static", 0),
            "llm": r.pop("latency_llm", 0),
            "runtime": r.pop("latency_runtime", 0),
        }
        records.append(r)

    return {"total": total, "records": records}


def list_batches(limit: int = 20) -> list:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM batch_scans ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]
