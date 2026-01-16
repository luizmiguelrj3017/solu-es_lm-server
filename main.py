from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import os, sqlite3
from datetime import datetime

APP = FastAPI()
DB_PATH = os.environ.get("LICENSE_DB", "license.db")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "troque-essa-chave")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS companies (
            company_key TEXT PRIMARY KEY,
            name TEXT,
            status TEXT,
            created_at TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            company_key TEXT,
            device_id TEXT,
            hostname TEXT,
            status TEXT,
            first_seen TEXT,
            last_seen TEXT,
            PRIMARY KEY (company_key, device_id)
        )
    """)
    conn.commit()
    conn.close()


@APP.on_event("startup")
def _startup():
    init_db()


class CheckReq(BaseModel):
    company_key: str
    device_id: str
    hostname: str | None = ""


class CheckResp(BaseModel):
    authorized: bool
    status: str
    message: str


def require_admin(x_admin_token: str | None):
    if not x_admin_token or x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")


@APP.get("/")
def root():
    return {"ok": True, "service": "ponto-do-acai-licenses"}


@APP.post("/api/check", response_model=CheckResp)
def check(req: CheckReq):
    now = datetime.utcnow().isoformat()
    company_key = (req.company_key or "").strip()
    device_id = (req.device_id or "").strip()
    hostname = (req.hostname or "").strip()

    if not company_key or not device_id:
        raise HTTPException(status_code=400, detail="company_key and device_id required")

    conn = db()
    c = conn.cursor()

    # company default: ACTIVE (para seu modelo: sem expirar sozinho)
    c.execute("SELECT company_key, status, name FROM companies WHERE company_key=?", (company_key,))
    row = c.fetchone()
    if not row:
        c.execute(
            "INSERT INTO companies (company_key, name, status, created_at) VALUES (?,?,?,?)",
            (company_key, company_key, "ACTIVE", now),
        )
        company_status = "ACTIVE"
    else:
        company_status = row[1] or "ACTIVE"

    # device: cria como PENDING se novo
    c.execute(
        "SELECT status FROM devices WHERE company_key=? AND device_id=?",
        (company_key, device_id),
    )
    drow = c.fetchone()
    if not drow:
        c.execute(
            "INSERT INTO devices (company_key, device_id, hostname, status, first_seen, last_seen) VALUES (?,?,?,?,?,?)",
            (company_key, device_id, hostname, "PENDING", now, now),
        )
        device_status = "PENDING"
    else:
        device_status = drow[0] or "PENDING"
        c.execute(
            "UPDATE devices SET hostname=?, last_seen=? WHERE company_key=? AND device_id=?",
            (hostname, now, company_key, device_id),
        )

    conn.commit()
    conn.close()

    if company_status != "ACTIVE":
        return CheckResp(authorized=False, status="COMPANY_BLOCKED", message="Empresa bloqueada pelo administrador")

    if device_status != "AUTHORIZED":
        return CheckResp(authorized=False, status=device_status, message="Aguardando autorizacao do administrador")

    return CheckResp(authorized=True, status="AUTHORIZED", message="OK")


class AdminCompanyReq(BaseModel):
    company_key: str
    name: str | None = None
    status: str | None = None  # ACTIVE / BLOCKED


@APP.post("/admin/company")
def admin_upsert_company(req: AdminCompanyReq, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    now = datetime.utcnow().isoformat()
    ck = (req.company_key or "").strip()
    if not ck:
        raise HTTPException(status_code=400, detail="company_key required")
    name = (req.name or ck).strip()
    status = (req.status or "ACTIVE").strip().upper()
    if status not in ("ACTIVE", "BLOCKED"):
        raise HTTPException(status_code=400, detail="status must be ACTIVE or BLOCKED")

    conn = db()
    c = conn.cursor()
    c.execute("SELECT company_key FROM companies WHERE company_key=?", (ck,))
    if c.fetchone():
        c.execute("UPDATE companies SET name=?, status=? WHERE company_key=?", (name, status, ck))
    else:
        c.execute(
            "INSERT INTO companies (company_key, name, status, created_at) VALUES (?,?,?,?)",
            (ck, name, status, now),
        )
    conn.commit(); conn.close()
    return {"ok": True, "company_key": ck, "status": status}


class AdminDeviceReq(BaseModel):
    company_key: str
    device_id: str


@APP.post("/admin/device/authorize")
def admin_authorize_device(req: AdminDeviceReq, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    ck = (req.company_key or "").strip(); did = (req.device_id or "").strip()
    if not ck or not did:
        raise HTTPException(status_code=400, detail="company_key and device_id required")
    conn = db(); c = conn.cursor()
    c.execute("UPDATE devices SET status='AUTHORIZED' WHERE company_key=? AND device_id=?", (ck, did))
    conn.commit(); conn.close()
    return {"ok": True}


@APP.post("/admin/device/revoke")
def admin_revoke_device(req: AdminDeviceReq, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    ck = (req.company_key or "").strip(); did = (req.device_id or "").strip()
    if not ck or not did:
        raise HTTPException(status_code=400, detail="company_key and device_id required")
    conn = db(); c = conn.cursor()
    c.execute("UPDATE devices SET status='REVOKED' WHERE company_key=? AND device_id=?", (ck, did))
    conn.commit(); conn.close()
    return {"ok": True}


@APP.get("/admin/devices")
def admin_list_devices(company_key: str, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    ck = (company_key or "").strip()
    conn = db(); c = conn.cursor()
    c.execute("SELECT device_id, hostname, status, first_seen, last_seen FROM devices WHERE company_key=? ORDER BY last_seen DESC", (ck,))
    rows = [
        {"device_id": r[0], "hostname": r[1], "status": r[2], "first_seen": r[3], "last_seen": r[4]}
        for r in c.fetchall()
    ]
    conn.close()
    return {"company_key": ck, "devices": rows}
    from fastapi.responses import HTMLResponse
from pathlib import Path

@app.get("/admin-panel", response_class=HTMLResponse)
def admin_panel():
    p = Path(__file__).with_name("admin.html")
    return HTMLResponse(p.read_text(encoding="utf-8"))

