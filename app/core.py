import os

APP_VERSION = "1.19.0"
import re
import httpx
import asyncio
import json
import uuid
import sqlite3
import secrets
import hashlib
import hmac
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, Response

app = FastAPI(title="DC1 Mover")

PORTAINER_URL = os.getenv("PORTAINER_URL", "").rstrip("/")
PORTAINER_TOKEN = os.getenv("PORTAINER_TOKEN", "")
headers = {"X-API-Key": PORTAINER_TOKEN}

VAS_HOSTING_API_KEY = os.getenv("VAS_HOSTING_API_KEY", "").strip()
VAS_HOSTING_API_URL = os.getenv("VAS_HOSTING_API_URL", "https://portal.vas-hosting.cz/api/v1").rstrip("/")

DB_PATH = "/data/mover.db"
MOVER_USER = os.getenv("MOVER_USER", "admin")
MOVER_PASSWORD = os.getenv("MOVER_PASSWORD", "")
SESSION_SECRET = os.getenv("MOVER_SESSION_SECRET", "")
SESSION_COOKIE = "dc1_mover_session"
sessions = {}

def password_hash(value, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", value.encode(), salt.encode(), 310000).hex()
    return salt + "$" + digest

def password_verify(value, stored):
    try:
        salt, expected = stored.split("$", 1)
        actual = password_hash(value, salt).split("$", 1)[1]
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False

def new_session():
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    sessions[token] = {"user": MOVER_USER, "csrf": csrf}
    return token, csrf

def user_permissions(username):
    with db() as conn:
        row = conn.execute("SELECT permissions FROM app_users WHERE username=? AND enabled=1", (username,)).fetchone()
    return set((row["permissions"] or "").split(",")) if row else set()

def require_permission(permission):
    def dependency(session=Depends(current_session)):
        if permission not in user_permissions(session.get("user", "")):
            raise HTTPException(403, "Permission denied")
        return session
    return dependency

def current_session(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    session = sessions.get(token)
    if not session:
        raise HTTPException(401, "Authentication required")
    return session

def require_csrf(request: Request, session=Depends(current_session)):
    supplied = request.headers.get("X-CSRF-Token", "")
    if not hmac.compare_digest(supplied, session["csrf"]):
        raise HTTPException(403, "Invalid CSRF token")
    return session

migration_jobs = {}

def utcnow():
    return datetime.now(timezone.utc).isoformat()

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS migrations (
                id TEXT PRIMARY KEY,
                stack_id INTEGER NOT NULL,
                target_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                steps_json TEXT NOT NULL,
                result_json TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS migration_locks (
                stack_id INTEGER PRIMARY KEY,
                job_id TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS endpoint_settings (
                endpoint_id INTEGER PRIMARY KEY,
                migration_enabled INTEGER NOT NULL DEFAULT 0,
                host_ip TEXT,
                site TEXT,
                public_ip TEXT,
                agent_url TEXT,
                agent_token TEXT,
                updated_at TEXT NOT NULL
            )
        """)
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(endpoint_settings)").fetchall()}
        if "public_ip" not in columns:
            conn.execute("ALTER TABLE endpoint_settings ADD COLUMN public_ip TEXT")
        if "agent_url" not in columns:
            conn.execute("ALTER TABLE endpoint_settings ADD COLUMN agent_url TEXT")
        if "agent_token" not in columns:
            conn.execute("ALTER TABLE endpoint_settings ADD COLUMN agent_token TEXT")
        if "role" not in columns:
            conn.execute("ALTER TABLE endpoint_settings ADD COLUMN role TEXT NOT NULL DEFAULT 'NONE'")
        if "lan_ip" not in columns:
            conn.execute("ALTER TABLE endpoint_settings ADD COLUMN lan_ip TEXT")
        conn.execute("""CREATE TABLE IF NOT EXISTS sites (
            name TEXT PRIMARY KEY,
            lan_cidr TEXT NOT NULL,
            management_octet INTEGER NOT NULL UNIQUE,
            public_ip TEXT,
            ssh_user TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""")
        conn.execute("CREATE TABLE IF NOT EXISTS stack_proxy_settings (stack_name TEXT PRIMARY KEY, host TEXT NOT NULL, service TEXT, container_port INTEGER, backend_port INTEGER, https INTEGER NOT NULL DEFAULT 1, updated_at TEXT NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, secret INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS app_users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, updated_at TEXT NOT NULL)")
        user_cols = {row["name"] for row in conn.execute("PRAGMA table_info(app_users)").fetchall()}
        if "permissions" not in user_cols:
            conn.execute("ALTER TABLE app_users ADD COLUMN permissions TEXT NOT NULL DEFAULT 'dashboard_read,migrations,dns_read,dns_write,admin'")
        if "enabled" not in user_cols:
            conn.execute("ALTER TABLE app_users ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")

def get_sites():
    with db() as conn:
        rows = conn.execute("SELECT * FROM sites ORDER BY management_octet, name").fetchall()
    return [dict(r) for r in rows]

def get_site(name):
    with db() as conn:
        row = conn.execute("SELECT * FROM sites WHERE upper(name)=upper(?)", (str(name or "").strip(),)).fetchone()
    return dict(row) if row else None

def next_management_octet():
    with db() as conn:
        row = conn.execute("SELECT COALESCE(MAX(management_octet), 1) AS value FROM sites").fetchone()
    return max(2, int(row["value"] or 1) + 1)

def save_site(name, lan_cidr, management_octet, public_ip="", ssh_user=""):
    name = str(name or "").strip().upper()
    with db() as conn:
        conn.execute("""INSERT INTO sites(name,lan_cidr,management_octet,public_ip,ssh_user,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET lan_cidr=excluded.lan_cidr,
            management_octet=excluded.management_octet, public_ip=excluded.public_ip,
            ssh_user=excluded.ssh_user, updated_at=excluded.updated_at""",
            (name, str(lan_cidr).strip(), int(management_octet), str(public_ip or "").strip(),
             str(ssh_user or "").strip(), utcnow(), utcnow()))
    return get_site(name)

def get_endpoint_settings():
    with db() as conn:
        rows = conn.execute("SELECT * FROM endpoint_settings").fetchall()
    return {int(r["endpoint_id"]): {"migration_enabled": bool(r["migration_enabled"]), "host_ip": r["host_ip"] or "", "lan_ip": r["lan_ip"] or "", "site": r["site"] or "", "public_ip": r["public_ip"] or "", "agent_url": r["agent_url"] or "", "agent_token": r["agent_token"] or "", "role": (r["role"] or "NONE").upper()} for r in rows}

def save_endpoint_setting(endpoint_id, migration_enabled, host_ip="", site="", public_ip="", agent_url="", agent_token=None, role="NONE", lan_ip=""):
    with db() as conn:
        conn.execute("""
            INSERT INTO endpoint_settings(endpoint_id, migration_enabled, host_ip, site, public_ip, agent_url, agent_token, role, lan_ip, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(endpoint_id) DO UPDATE SET migration_enabled=excluded.migration_enabled,
            host_ip=excluded.host_ip, site=excluded.site, public_ip=excluded.public_ip, agent_url=excluded.agent_url,
            agent_token=CASE WHEN excluded.agent_token IS NULL THEN endpoint_settings.agent_token ELSE excluded.agent_token END,
            role=excluded.role, lan_ip=CASE WHEN excluded.lan_ip != '' THEN excluded.lan_ip ELSE endpoint_settings.lan_ip END, updated_at=excluded.updated_at
        """, (int(endpoint_id), 1 if migration_enabled else 0, (host_ip or "").strip(), (site or "").strip(), (public_ip or "").strip(),
              (agent_url or "").strip().rstrip("/"), agent_token, (role or "NONE").upper(), (lan_ip or "").strip(), utcnow()))

def get_stack_proxy_setting(stack_name):
    with db() as conn:
        row = conn.execute("SELECT * FROM stack_proxy_settings WHERE stack_name = ?", (str(stack_name),)).fetchone()
    return dict(row) if row else None

def save_stack_proxy_setting(stack_name, host, service="", container_port=None, backend_port=None, https=True):
    with db() as conn:
        conn.execute("""INSERT INTO stack_proxy_settings(stack_name,host,service,container_port,backend_port,https,updated_at)
            VALUES(?,?,?,?,?,?,?) ON CONFLICT(stack_name) DO UPDATE SET host=excluded.host, service=excluded.service,
            container_port=excluded.container_port, backend_port=excluded.backend_port, https=excluded.https, updated_at=excluded.updated_at""",
            (str(stack_name), str(host).strip().lower().rstrip("."), str(service or ""), int(container_port) if container_port else None,
             int(backend_port) if backend_port else None, 1 if https else 0, utcnow()))

def delete_stack_proxy_setting(stack_name):
    with db() as conn:
        conn.execute("DELETE FROM stack_proxy_settings WHERE stack_name = ?", (str(stack_name),))

def migration_endpoints(endpoints):
    settings = get_endpoint_settings()
    return [e for e in endpoints if settings.get(int(e["Id"]), {}).get("migration_enabled", False) and settings.get(int(e["Id"]), {}).get("role","NODE") == "NODE"]

def acquire_stack_lock(stack_id, job_id):
    try:
        with db() as conn:
            conn.execute("INSERT INTO migration_locks(stack_id, job_id, created_at) VALUES (?, ?, ?)", (stack_id, job_id, utcnow()))
        return True
    except sqlite3.IntegrityError:
        return False

def release_stack_lock(stack_id, job_id):
    with db() as conn:
        conn.execute("DELETE FROM migration_locks WHERE stack_id = ? AND job_id = ?", (stack_id, job_id))

def persist_job(job):
    now = utcnow(); job["updated_at"] = now; job.setdefault("created_at", now)
    with db() as conn:
        conn.execute("""
            INSERT INTO migrations (id, stack_id, target_id, status, steps_json, result_json, error, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET status=excluded.status, steps_json=excluded.steps_json,
            result_json=excluded.result_json, error=excluded.error, updated_at=excluded.updated_at
        """, (job["id"], job["stack_id"], job["target_id"], job["status"], json.dumps(job.get("steps", [])), json.dumps(job.get("result")) if job.get("result") is not None else None, job.get("error"), job["created_at"], job["updated_at"]))

def load_job(job_id):
    if job_id in migration_jobs: return migration_jobs[job_id]
    with db() as conn:
        row = conn.execute("SELECT * FROM migrations WHERE id = ?", (job_id,)).fetchone()
    if not row: return None
    job = {"id": row["id"], "stack_id": row["stack_id"], "target_id": row["target_id"], "status": row["status"], "steps": json.loads(row["steps_json"] or "[]"), "result": json.loads(row["result_json"]) if row["result_json"] else None, "error": row["error"], "created_at": row["created_at"], "updated_at": row["updated_at"]}
    migration_jobs[job_id] = job
    return job

def load_recent_jobs(limit=50):
    with db() as conn:
        rows = conn.execute("SELECT id FROM migrations ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [load_job(row["id"]) for row in rows]

def new_job(stack_id, target_id):
    job_id = uuid.uuid4().hex
    job = {"id": job_id, "stack_id": stack_id, "target_id": target_id, "status": "queued", "steps": [], "result": None, "error": None, "created_at": utcnow(), "updated_at": utcnow()}
    if not acquire_stack_lock(stack_id, job_id): raise HTTPException(409, "Tento stack už má aktivní migraci")
    migration_jobs[job_id] = job; persist_job(job); return job

def job_step(job, name, state, message=""):
    existing = next((s for s in job["steps"] if s["name"] == name), None)
    payload = {"name": name, "state": state, "message": message}
    if existing: existing.update(payload)
    else: job["steps"].append(payload)
    persist_job(job)

def setting_get(key, default=""):
    with db() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default

def setting_set(key, value, secret=False):
    with db() as conn:
        conn.execute("INSERT INTO app_settings(key,value,secret,updated_at) VALUES(?,?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, secret=excluded.secret, updated_at=excluded.updated_at", (key, str(value or ""), 1 if secret else 0, utcnow()))

def setup_required():
    with db() as conn:
        return conn.execute("SELECT 1 FROM app_users LIMIT 1").fetchone() is None

def create_admin(username, password):
    if not username or len(password) < 10:
        raise ValueError("Username is required and password must have at least 10 characters")
    with db() as conn:
        conn.execute("INSERT INTO app_users(username,password_hash,updated_at,permissions,enabled) VALUES(?,?,?,?,1)", (username.strip(), password_hash(password), utcnow(), "dashboard_read,migrations,dns_read,dns_write,admin"))

def authenticate(username, password):
    with db() as conn:
        row = conn.execute("SELECT password_hash, enabled FROM app_users WHERE username = ?", (username,)).fetchone()
    if row:
        return bool(row["enabled"]) and password_verify(password, row["password_hash"])
    return bool(MOVER_PASSWORD) and hmac.compare_digest(username, MOVER_USER) and hmac.compare_digest(password, MOVER_PASSWORD)

init_db()
PORTAINER_URL = setting_get("portainer_url", PORTAINER_URL).rstrip("/")
PORTAINER_TOKEN = setting_get("portainer_token", PORTAINER_TOKEN)
VAS_HOSTING_API_KEY = setting_get("vas_hosting_api_key", VAS_HOSTING_API_KEY)
VAS_HOSTING_API_URL = setting_get("vas_hosting_api_url", VAS_HOSTING_API_URL).rstrip("/")
headers = {"X-API-Key": PORTAINER_TOKEN}

def portainer_config():
    url = setting_get("portainer_url", PORTAINER_URL).rstrip("/")
    token = setting_get("portainer_token", PORTAINER_TOKEN)
    if not url or not token:
        raise HTTPException(503, "Portainer is not configured")
    return url, token

def client():
    url, token = portainer_config()
    return httpx.AsyncClient(base_url=url, headers={"X-API-Key": token}, verify=False, timeout=30)

async def pget(path, params=None):
    async with client() as c:
        r = await c.get(path, params=params)
        if r.status_code != 200: raise HTTPException(r.status_code, r.text)
        return r.json()

async def get_endpoints(): return await pget("/api/endpoints")
async def get_stacks(): return await pget("/api/stacks")

async def docker_get(endpoint_id, path, params=None, allowed=(200,)):
    async with client() as c:
        r = await c.get("/api/endpoints/" + str(endpoint_id) + "/docker" + path, params=params)
        if r.status_code not in allowed: raise HTTPException(r.status_code, "Docker API error: " + r.text)
        return r

async def docker_request(endpoint_id, method, path, **kwargs):
    async with client() as c:
        url = "/api/endpoints/" + str(endpoint_id) + "/docker" + path
        if method.upper() == "POST" and path.endswith("/start") and "json" not in kwargs and "content" not in kwargs and "data" not in kwargs and "files" not in kwargs:
            # Portainer's reverse proxy can turn a header-only POST into a request
            # Docker treats as a non-empty body. Use the Docker API compatibility
            # query endpoint: POST is still body-less, with all data in the URL.
            params = kwargs.pop("params", None)
            request = httpx.Request("POST", str(c.base_url).rstrip("/") + url, params=params, headers={"X-API-Key": portainer_config()[1]})
            return await c.send(request)
        return await c.request(method, url, **kwargs)

async def wait_container(endpoint_id, container_id, timeout=300):
    async with client() as c:
        r = await c.post("/api/endpoints/" + str(endpoint_id) + "/docker/containers/" + container_id + "/wait", json={"condition": "not-running"}, timeout=timeout)
        if r.status_code != 200: raise HTTPException(r.status_code, r.text)
        return int(r.json().get("StatusCode", 1))

async def remove_container(endpoint_id, container_id):
    async with client() as c:
        await c.delete("/api/endpoints/" + str(endpoint_id) + "/docker/containers/" + container_id, params={"force": "1", "v": "0"})

async def ensure_image(endpoint_id, image):
    async with client() as c:
        r = await c.post("/api/endpoints/" + str(endpoint_id) + "/docker/images/create", params={"fromImage": image}, timeout=300)
        if r.status_code not in (200, 201): raise HTTPException(r.status_code, "Image pull failed: " + r.text)

async def create_volume(endpoint_id, name, driver="local"):
    async with client() as c:
        r = await c.post("/api/endpoints/" + str(endpoint_id) + "/docker/volumes/create", json={"Name": name, "Driver": driver or "local"})
        if r.status_code not in (200, 201): raise HTTPException(r.status_code, "Volume create failed: " + r.text)
        return r.json()

async def _run_volume_copy_helper(endpoint_id, name, mounts, command, network_mode=None):
    helper_image = "alpine:3.22"
    await ensure_image(endpoint_id, helper_image)
    host_config = {"Mounts": mounts}
    if network_mode:
        host_config["NetworkMode"] = network_mode
    r = await docker_request(endpoint_id, "POST", "/containers/create", params={"name": name},
        json={"Image": helper_image, "Cmd": ["sh", "-c", command], "HostConfig": host_config})
    if r.status_code != 201:
        raise HTTPException(r.status_code, "Volume helper create failed: " + r.text)
    return r.json()["Id"]

async def copy_volume_local(endpoint_id, volume_name, target_volume_name):
    """Copy a volume entirely on one Docker host. No payload traverses Portainer/DSM."""
    name = "dsm-local-copy-" + uuid.uuid4().hex[:10]
    cid = None
    try:
        cid = await _run_volume_copy_helper(endpoint_id, name, [
            {"Type": "volume", "Source": volume_name, "Target": "/source", "ReadOnly": True},
            {"Type": "volume", "Source": target_volume_name, "Target": "/target"},
        ], "cd /source && tar -cf - . | tar -C /target -xf -")
        r = await docker_request(endpoint_id, "POST", "/containers/" + cid + "/start", json={})
        if r.status_code not in (204, 304):
            raise HTTPException(r.status_code, "Local volume copy start failed: " + r.text)
        code = await wait_container(endpoint_id, cid, timeout=86400)
        if code != 0:
            logs = await docker_request(endpoint_id, "GET", "/containers/" + cid + "/logs", params={"stdout":"1","stderr":"1","tail":"80"})
            raise RuntimeError("Local volume copy failed (exit " + str(code) + "): " + logs.text[-2000:])
        return {"mode": "local", "transport": "node-local"}
    finally:
        if cid:
            try: await remove_container(endpoint_id, cid)
            except Exception: pass

def _endpoint_transfer_ip(endpoint_id, peer_id):
    settings = get_endpoint_settings()
    src = settings.get(int(endpoint_id), {})
    peer = settings.get(int(peer_id), {})
    same_site = bool(src.get("site")) and str(src.get("site")).strip().upper() == str(peer.get("site") or "").strip().upper()
    if same_site:
        return (src.get("lan_ip") or src.get("host_ip") or "").strip(), "LAN"
    return (src.get("host_ip") or src.get("lan_ip") or "").strip(), "WireGuard"

async def copy_volume_direct(source_id, target_id, volume_name, target_volume_name):
    """Stream tar directly NODE->NODE. DSM only orchestrates helper containers."""
    source_ip, network = _endpoint_transfer_ip(source_id, target_id)
    if not source_ip:
        raise RuntimeError("Direct volume transfer: source LAN/WireGuard IP is not configured")
    port = 49152 + secrets.randbelow(1024)
    src_name = "dsm-send-" + uuid.uuid4().hex[:10]
    dst_name = "dsm-recv-" + uuid.uuid4().hex[:10]
    src_id = dst_id = None
    try:
        src_id = await _run_volume_copy_helper(source_id, src_name, [
            {"Type": "volume", "Source": volume_name, "Target": "/source", "ReadOnly": True}
        ], "set -o pipefail; cd /source && tar -cf - . | nc -l -p " + str(port), "host")
        dst_id = await _run_volume_copy_helper(target_id, dst_name, [
            {"Type": "volume", "Source": target_volume_name, "Target": "/target"}
        ], "set -o pipefail; nc " + source_ip + " " + str(port) + " | tar -C /target -xf -", "host")
        r = await docker_request(source_id, "POST", "/containers/" + src_id + "/start", json={})
        if r.status_code not in (204, 304):
            raise HTTPException(r.status_code, "Source transfer helper start failed: " + r.text)
        await asyncio.sleep(1)
        r = await docker_request(target_id, "POST", "/containers/" + dst_id + "/start", json={})
        if r.status_code not in (204, 304):
            raise HTTPException(r.status_code, "Target transfer helper start failed: " + r.text)
        dst_code = await wait_container(target_id, dst_id, timeout=86400)
        src_code = await wait_container(source_id, src_id, timeout=86400)
        if dst_code != 0 or src_code != 0:
            raise RuntimeError("Direct volume transfer failed: sender exit=" + str(src_code) + ", receiver exit=" + str(dst_code))
        return {"mode": "direct", "transport": network, "source_ip": source_ip, "port": port}
    finally:
        for eid, cid in ((source_id, src_id), (target_id, dst_id)):
            if cid:
                try:
                    await remove_container(eid, cid)
                except Exception:
                    pass

async def copy_volume(source_id, target_id, volume_name, target_volume_name=None):
    target_volume_name = target_volume_name or volume_name
    if int(source_id) == int(target_id):
        return await copy_volume_local(source_id, volume_name, target_volume_name)
    return await copy_volume_direct(source_id, target_id, volume_name, target_volume_name)

async def get_stack_file(stack_id):
    async with client() as c:
        r = await c.get("/api/stacks/" + str(stack_id) + "/file")
        if r.status_code != 200: raise HTTPException(r.status_code, "Cannot read stack file: " + r.text)
        return r.json().get("StackFileContent", "")

async def stop_stack(stack_id, endpoint_id):
    async with client() as c:
        r = await c.post("/api/stacks/" + str(stack_id) + "/stop", params={"endpointId": endpoint_id})
        if r.status_code not in (200, 204): raise HTTPException(r.status_code, "Cannot stop source stack: " + r.text)

async def start_stack(stack_id, endpoint_id):
    async with client() as c:
        r = await c.post("/api/stacks/" + str(stack_id) + "/start", params={"endpointId": endpoint_id})
        if r.status_code not in (200, 204): raise HTTPException(r.status_code, "Cannot start source stack: " + r.text)

async def create_target_stack(target_id, name, stack_file, env):
    async with client() as c:
        r = await c.post("/api/stacks/create/standalone/string", params={"endpointId": target_id}, json={"Name": name, "StackFileContent": stack_file, "Env": env or []}, timeout=120)
        if r.status_code not in (200, 201): raise HTTPException(r.status_code, "Target stack create failed: " + r.text)
        return r.json()

async def build_detail(stack_id):
    stacks = await get_stacks(); endpoints = await get_endpoints(); stack = next((s for s in stacks if s["Id"] == stack_id), None)
    if not stack: raise HTTPException(404, "Stack not found")
    endpoint_id = stack["EndpointId"]; endpoint = next((e for e in endpoints if e["Id"] == endpoint_id), None)
    all_containers = (await docker_get(endpoint_id, "/containers/json", params={"all": "1"})).json(); containers = []
    for container in all_containers:
        labels = container.get("Labels") or {}
        if labels.get("com.docker.compose.project") != stack["Name"]: continue
        mounts = [{"type": m.get("Type"), "name": m.get("Name"), "source": m.get("Source"), "destination": m.get("Destination"), "rw": m.get("RW")} for m in container.get("Mounts", [])]
        ports = [{"ip": p.get("IP"), "private": p.get("PrivatePort"), "public": p.get("PublicPort"), "type": p.get("Type")} for p in container.get("Ports", [])]
        containers.append({"id": container["Id"][:12], "name": container.get("Names", ["unknown"])[0].lstrip("/"), "image": container.get("Image"), "state": container.get("State"), "status": container.get("Status"), "mounts": mounts, "ports": ports, "labels": labels})
    volume_names = sorted({m["name"] for c in containers for m in c["mounts"] if m["type"] == "volume" and m["name"]}); volumes = []
    for volume_name in volume_names:
        r = await docker_get(endpoint_id, "/volumes/" + volume_name, allowed=(200, 404))
        if r.status_code == 200:
            v = r.json(); volumes.append({"name": v.get("Name"), "driver": v.get("Driver"), "mountpoint": v.get("Mountpoint")})
        else: volumes.append({"name": volume_name, "driver": "unknown", "mountpoint": None})
    domains = []
    managed_proxy = get_stack_proxy_setting(stack["Name"])
    if managed_proxy:
        domains.append({"host": managed_proxy.get("host"), "port": managed_proxy.get("backend_port"),
                        "container_port": managed_proxy.get("container_port"), "service": managed_proxy.get("service"),
                        "scheme": "http", "https": bool(managed_proxy.get("https")), "managed": True})
    else:
        for container in containers:
            labels = container["labels"]
            if labels.get("dc1.proxy.enable") == "true":
                domains.append({"host": labels.get("dc1.proxy.host"), "port": labels.get("dc1.proxy.port"), "scheme": labels.get("dc1.proxy.scheme", "http")})
    endpoint_name = endpoint["Name"] if endpoint else "Endpoint " + str(endpoint_id)
    return {"stack": {"id": stack["Id"], "name": stack["Name"], "endpoint_id": endpoint_id, "endpoint": endpoint_name, "status": stack["Status"]}, "containers": containers, "volumes": volumes, "domains": domains}


def vas_config():
    return setting_get("vas_hosting_api_url", VAS_HOSTING_API_URL).rstrip("/"), setting_get("vas_hosting_api_key", VAS_HOSTING_API_KEY)

def vas_hosting_enabled():
    return bool(vas_config()[1])

def split_dns_name(host):
    host = (host or "").strip().rstrip(".").lower()
    if not host or "." not in host:
        raise RuntimeError("Invalid DNS host: " + host)
    labels = host.split(".")
    # Try longest managed zone first via the provider API.
    return host, [".".join(labels[i:]) for i in range(1, len(labels) - 1)] + [".".join(labels[-2:])]

async def vas_dns_records(zone):
    if not vas_hosting_enabled():
        raise RuntimeError("Váš Hosting DNS is not configured")
    api_url, api_key = vas_config()
    async with httpx.AsyncClient(base_url=api_url, headers={"X-API-Key": api_key}, timeout=30) as c:
        r = await c.get("/domains/" + zone + "/dns-records")
        if r.status_code != 200:
            raise RuntimeError("Váš Hosting DNS list failed for " + zone + ": HTTP " + str(r.status_code))
        data = r.json()
        return [{"id": str(record_id), **record} for record_id, record in data.items()]

async def vas_find_a_record(host):
    fqdn, zones = split_dns_name(host)
    last_error = None
    for zone in zones:
        try:
            records = await vas_dns_records(zone)
        except Exception as exc:
            last_error = exc
            continue
        matches = [r for r in records if (r.get("name") or "").rstrip(".").lower() == fqdn and r.get("type") == "A"]
        if len(matches) > 1:
            raise RuntimeError("Multiple A records found for " + fqdn + "; automatic DNS cutover is ambiguous")
        if matches:
            return zone, matches[0]
    if last_error:
        raise RuntimeError("DNS zone/record not found for " + fqdn + ": " + str(last_error))
    raise RuntimeError("A record not found for " + fqdn)

async def vas_update_a_record(zone, record_id, host, content, ttl=60):
    if not vas_hosting_enabled():
        raise RuntimeError("Váš Hosting DNS is not configured")
    fqdn = host.rstrip(".")
    relative_name = fqdn[:-len(zone)-1] if fqdn.endswith("." + zone) else ("" if fqdn == zone else fqdn)
    payload = {"name": relative_name or zone, "content": content, "type": "A", "ttl": int(ttl or 60)}
    api_url, api_key = vas_config()
    async with httpx.AsyncClient(base_url=api_url, headers={"X-API-Key": api_key, "Content-Type": "application/json"}, timeout=30) as c:
        r = await c.post("/domains/" + zone + "/dns-records/" + str(record_id), json=payload)
        if r.status_code not in (200, 201, 204):
            raise RuntimeError("Váš Hosting DNS update failed for " + host + ": HTTP " + str(r.status_code) + " " + r.text[:300])
    _, verified = await vas_find_a_record(host)
    if verified.get("content") != content:
        raise RuntimeError("DNS update verification failed for " + host + ": expected " + content + ", got " + str(verified.get("content")))
    return verified
