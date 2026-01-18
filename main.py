import os
import sqlite3
import time
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from pathlib import Path

# =========================================================
# App
# =========================================================
APP = FastAPI()

# =========================================================
# Config
# =========================================================
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
DB_PATH = os.getenv("LICENSE_DB", "license.db")

# =========================================================
# DB Helpers
# =========================================================
def get_db():
    # check_same_thread=False ajuda em alguns ambientes com múltiplas threads
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def now_ts() -> int:
    return int(time.time())

def init_db():
    with get_db() as con:
        cur = con.cursor()

        # Tabela (versão nova com campos extras)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                company_key     TEXT NOT NULL,
                device_id       TEXT NOT NULL,
                hostname        TEXT,
                pc_name         TEXT,
                requester_name  TEXT,
                establishment   TEXT,
                status          TEXT NOT NULL,
                created_at      INTEGER,
                updated_at      INTEGER,
                PRIMARY KEY (company_key, device_id)
            )
        """)

        # Migração para DB antigo (adiciona colunas se faltarem)
        cur.execute("PRAGMA table_info(devices)")
        cols = {row[1] for row in cur.fetchall()}

        if "pc_name" not in cols:
            cur.execute("ALTER TABLE devices ADD COLUMN pc_name TEXT")
        if "requester_name" not in cols:
            cur.execute("ALTER TABLE devices ADD COLUMN requester_name TEXT")
        if "establishment" not in cols:
            cur.execute("ALTER TABLE devices ADD COLUMN establishment TEXT")

        con.commit()

init_db()

# =========================================================
# Models
# =========================================================
class CheckPayload(BaseModel):
    company_key: str
    device_id: str
    hostname: Optional[str] = None

    # Novos campos (para identificar solicitante e PC)
    pc_name: Optional[str] = None
    requester_name: Optional[str] = None
    establishment: Optional[str] = None

    ts: Optional[int] = None

class AdminDeviceAction(BaseModel):
    company_key: str
    device_id: str

# =========================================================
# Utils
# =========================================================
def require_admin(x_admin_token: Optional[str]):
    if not ADMIN_TOKEN or x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

# =========================================================
# Public
# =========================================================
@APP.get("/health")
def health():
    return {"status": "ok"}

# Render está com Health Check em /healthz
@APP.get("/healthz")
def healthz():
    return {"status": "ok"}

@APP.post("/api/check")
def api_check(payload: CheckPayload):
    """
    POS chama este endpoint ao iniciar.
    - AUTHORIZED -> authorized: true
    - PENDING/REVOKED -> authorized: false
    - Primeira vez: cria registro PENDING (salva Nome/Estabelecimento/PC)
    """
    with get_db() as con:
        cur = con.cursor()

        cur.execute(
            "SELECT status FROM devices WHERE company_key=? AND device_id=?",
            (payload.company_key, payload.device_id)
        )
        row = cur.fetchone()

        if row is None:
            # Primeira vez: cria como PENDING
            cur.execute(
                """
                INSERT OR REPLACE INTO devices
                (company_key, device_id, hostname, pc_name, requester_name, establishment, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.company_key,
                    payload.device_id,
                    payload.hostname,
                    payload.pc_name,
                    payload.requester_name,
                    payload.establishment,
                    "PENDING",
                    now_ts(),
                    now_ts(),
                )
            )
            con.commit()
            return {
                "authorized": False,
                "status": "PENDING",
                "message": "Aguardando autorização do administrador"
            }

        status = row[0]

        # Atualiza dados do device SEM travar em strings vazias.
        # Se no banco estiver "", tratamos como NULL (NULLIF) para permitir atualização posterior.
        cur.execute(
            """
            UPDATE devices
            SET hostname = COALESCE(NULLIF(hostname, ''), ?),
                pc_name = COALESCE(NULLIF(pc_name, ''), ?),
                requester_name = COALESCE(NULLIF(requester_name, ''), ?),
                establishment = COALESCE(NULLIF(establishment, ''), ?),
                updated_at = ?
            WHERE company_key=? AND device_id=?
            """,
            (
                payload.hostname,
                payload.pc_name,
                payload.requester_name,
                payload.establishment,
                now_ts(),
                payload.company_key,
                payload.device_id,
            )
        )
        con.commit()

        if status == "AUTHORIZED":
            return {"authorized": True}

        return {
            "authorized": False,
            "status": status,
            "message": "Aguardando autorização do administrador"
        }

# =========================================================
# Admin
# =========================================================
@APP.get("/admin/devices")
def admin_list_devices(
    company_key: str,
    x_admin_token: Optional[str] = Header(None)
):
    require_admin(x_admin_token)
    with get_db() as con:
        cur = con.cursor()
        cur.execute(
            """
            SELECT company_key, device_id, hostname, pc_name, requester_name, establishment,
                   status, created_at, updated_at
            FROM devices
            WHERE company_key=?
            ORDER BY updated_at DESC
            """,
            (company_key,)
        )
        rows = cur.fetchall()
        return [
            {
                "company_key": r[0],
                "device_id": r[1],
                "hostname": r[2],
                "pc_name": r[3],
                "requester_name": r[4],
                "establishment": r[5],
                "status": r[6],
                "created_at": r[7],
                "updated_at": r[8],
            }
            for r in rows
        ]

@APP.post("/admin/device/authorize")
def admin_authorize(
    payload: AdminDeviceAction,
    x_admin_token: Optional[str] = Header(None)
):
    require_admin(x_admin_token)
    with get_db() as con:
        cur = con.cursor()
        cur.execute(
            """
            UPDATE devices
            SET status='AUTHORIZED', updated_at=?
            WHERE company_key=? AND device_id=?
            """,
            (now_ts(), payload.company_key, payload.device_id)
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Device not found")
        con.commit()
    return {"ok": True}

@APP.post("/admin/device/revoke")
def admin_revoke(
    payload: AdminDeviceAction,
    x_admin_token: Optional[str] = Header(None)
):
    require_admin(x_admin_token)
    with get_db() as con:
        cur = con.cursor()
        cur.execute(
            """
            UPDATE devices
            SET status='REVOKED', updated_at=?
            WHERE company_key=? AND device_id=?
            """,
            (now_ts(), payload.company_key, payload.device_id)
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Device not found")
        con.commit()
    return {"ok": True}

# =========================================================
# Admin Panel (HTML)
# =========================================================
@APP.get("/admin-panel", response_class=HTMLResponse)
def admin_panel():
    p = Path(__file__).with_name("admin.html")
    if not p.exists():
        raise HTTPException(status_code=404, detail="admin.html not found")
    return HTMLResponse(p.read_text(encoding="utf-8"))
