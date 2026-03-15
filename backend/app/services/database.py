import sqlite3
import aiosqlite
import os
import uuid
import datetime
import json

# Database path: backend/data/seccodereview.db
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DATA_DIR = os.path.join(_BASE_DIR, "data")
if not os.path.exists(_DATA_DIR):
    os.makedirs(_DATA_DIR)

DB_PATH = os.path.join(_DATA_DIR, "seccodereview.db")


async def init_db():
    """Initialize the SQLite database schema."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute('''
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            absolute_path TEXT UNIQUE NOT NULL,
            created_at TEXT,
            last_scanned TEXT,
            current_stage TEXT,
            progress_metadata TEXT DEFAULT '{}'
        )
        ''')
        
        await db.execute('''
        CREATE TABLE IF NOT EXISTS audits (
            id TEXT PRIMARY KEY,
            project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
            timestamp TEXT NOT NULL,
            report_path TEXT,
            status TEXT DEFAULT 'completed',
            total_findings INTEGER DEFAULT 0,
            critical INTEGER DEFAULT 0,
            high INTEGER DEFAULT 0,
            medium INTEGER DEFAULT 0,
            low INTEGER DEFAULT 0
        )
        ''')

        await db.execute('''
        CREATE TABLE IF NOT EXISTS audit_metrics (
            id TEXT PRIMARY KEY,
            audit_id TEXT REFERENCES audits(id) ON DELETE CASCADE,
            architecture INTEGER DEFAULT 0,
            iam INTEGER DEFAULT 0,
            data_flow INTEGER DEFAULT 0,
            business_logic INTEGER DEFAULT 0,
            iac INTEGER DEFAULT 0,
            compliance INTEGER DEFAULT 0
        )
        ''')
        
        await db.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
        ''')
        
        await db.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
            protocol_id TEXT NOT NULL,
            file_path TEXT NOT NULL,
            line_number TEXT NOT NULL,
            code_snippet TEXT,
            severity TEXT,
            description TEXT,
            attack_scenario TEXT,
            timestamp TEXT NOT NULL
        )
        ''')
        
        # Add current_stage if missing (schema evolution support for existing SQLite file)
        try:
            await db.execute("ALTER TABLE projects ADD COLUMN current_stage TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists
            
        # Add progress_metadata if missing
        try:
            await db.execute("ALTER TABLE projects ADD COLUMN progress_metadata TEXT DEFAULT '{}'")
        except sqlite3.OperationalError:
            pass
            
        await db.commit()

def get_db_connection():
    """Returns a new aiosqlite connection to the database. Use async with get_db_connection() as db:"""
    return aiosqlite.connect(DB_PATH)


# --- Projects CRUD ---

async def upsert_project(name: str, absolute_path: str) -> str:
    """Create or update a project by path, returning its UUID."""
    abs_path = os.path.abspath(absolute_path)
    now = datetime.datetime.utcnow().isoformat()
    
    async with aiosqlite.connect(DB_PATH) as db:
        # Check if exists
        async with db.execute("SELECT id FROM projects WHERE absolute_path = ?", (abs_path,)) as cursor:
            row = await cursor.fetchone()
            
        if row:
            pid = row[0]
            await db.execute("UPDATE projects SET name = ?, last_scanned = ? WHERE id = ?", (name, now, pid))
            await db.commit()
            return pid
            
        pid = str(uuid.uuid4())
        await db.execute(
            "INSERT INTO projects (id, name, absolute_path, created_at, last_scanned) VALUES (?, ?, ?, ?, ?)",
            (pid, name, abs_path, now, now)
        )
        await db.commit()
        return pid


async def get_all_projects() -> list[dict]:
    """Get all standard projects."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM projects ORDER BY last_scanned DESC") as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]


async def get_project_by_path(absolute_path: str) -> dict | None:
    abs_path = os.path.abspath(absolute_path)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM projects WHERE absolute_path = ?", (abs_path,)) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            res = dict(row)
            try:
                res["progress_metadata"] = json.loads(res.get("progress_metadata", "{}"))
            except:
                res["progress_metadata"] = {}
            return res

async def update_progress_metadata(project_id: str, stage: str, data: dict):
    """Perform a partial update of the progress_metadata JSON column."""
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT progress_metadata FROM projects WHERE id = ?", (project_id,)) as cursor:
            row = await cursor.fetchone()
            
        if not row:
            return
            
        try:
            current_metadata = json.loads(row[0] or "{}")
        except:
            current_metadata = {}
            
        current_metadata[stage] = data
        new_metadata_str = json.dumps(current_metadata)
        
        await db.execute("UPDATE projects SET progress_metadata = ? WHERE id = ?", (new_metadata_str, project_id))
        await db.commit()


# --- Audits & Metrics CRUD ---

async def create_audit(
    project_id: str, 
    report_path: str, 
    status: str, 
    findings_stats: dict, 
    metrics: dict
) -> str:
    """Create a new audit and its metrics."""
    audit_id = str(uuid.uuid4())
    now = datetime.datetime.utcnow().isoformat()
    
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO audits 
            (id, project_id, timestamp, report_path, status, total_findings, critical, high, medium, low) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                audit_id, project_id, now, report_path, status,
                findings_stats.get("total", 0),
                findings_stats.get("critical", 0),
                findings_stats.get("high", 0),
                findings_stats.get("medium", 0),
                findings_stats.get("low", 0),
            )
        )
        
        metrics_id = str(uuid.uuid4())
        await db.execute(
            """INSERT INTO audit_metrics 
            (id, audit_id, architecture, iam, data_flow, business_logic, iac, compliance) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                metrics_id, audit_id,
                metrics.get("architecture", 0),
                metrics.get("iam", 0),
                metrics.get("data_flow", 0),
                metrics.get("business_logic", 0),
                metrics.get("iac", 0),
                metrics.get("compliance", 0),
            )
        )
        await db.commit()
        return audit_id


async def get_audits_for_project(project_id: str) -> list[dict]:
    """Get all audits and their metrics for a project."""
    query = """
    SELECT a.*, 
           m.architecture, m.iam, m.data_flow, m.business_logic, m.iac, m.compliance 
    FROM audits a
    LEFT JOIN audit_metrics m ON a.id = m.audit_id
    WHERE a.project_id = ?
    ORDER BY a.timestamp DESC
    """
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(query, (project_id,)) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

# --- Audit Logs & Session State ---

async def append_audit_log(project_id: str, level: str, message: str) -> None:
    """Append a streaming log entry."""
    lid = str(uuid.uuid4())
    now = datetime.datetime.utcnow().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO audit_logs (id, project_id, level, message, timestamp) VALUES (?, ?, ?, ?, ?)",
            (lid, project_id, level, message, now)
        )
        await db.commit()

async def get_session_logs(project_id: str) -> list[dict]:
    """Retrieve all logs for the current active session of a project."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM audit_logs WHERE project_id = ? ORDER BY timestamp ASC", 
            (project_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

async def clear_session_logs(project_id: str) -> None:
    """Clear the streaming logs for a project to start fresh."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM audit_logs WHERE project_id = ?", (project_id,))
        # Also reset current_stage
        await db.execute("UPDATE projects SET current_stage = NULL WHERE id = ?", (project_id,))
        await db.commit()

async def update_project_stage(project_id: str, stage: str) -> None:
    """Update the current scanning stage of a project."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE projects SET current_stage = ? WHERE id = ?", (stage, project_id))
        await db.commit()

# --- Findings CRUD ---

async def add_finding(project_id: str, protocol_id: str, file_path: str, line_number: str, code_snippet: str, severity: str, description: str, attack_scenario: str = "") -> str | None:
    """
    Save a finding to the DB. Skip if a finding with the same protocol_id, file_path, and line_number already exists for this project.
    Returns the UUID of the inserted finding, or None if it was skipped (already exists).
    """
    now = datetime.datetime.utcnow().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT id, description FROM findings WHERE project_id = ? AND protocol_id = ? AND file_path = ? AND line_number = ?",
            (project_id, protocol_id, file_path, line_number)
        ) as cursor:
            row = await cursor.fetchone()
            
        if row:
            fid, existing_desc = row[0], row[1]
            if description[:100] not in existing_desc:
                new_desc = existing_desc + f"\n---\n{description}"
                await db.execute("UPDATE findings SET description = ? WHERE id = ?", (new_desc, fid))
                await db.commit()
            return None # Skipped due to conflict, detail merged
            
        fid = str(uuid.uuid4())
        await db.execute(
            """INSERT INTO findings 
            (id, project_id, protocol_id, file_path, line_number, code_snippet, severity, description, attack_scenario, timestamp) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (fid, project_id, protocol_id, file_path, line_number, code_snippet, severity, description, attack_scenario, now)
        )
        await db.commit()
        return fid

async def get_findings_for_project(project_id: str) -> list[dict]:
    """Retrieve all findings for a given project."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM findings WHERE project_id = ? ORDER BY timestamp ASC", (project_id,)) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]
