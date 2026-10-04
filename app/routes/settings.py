from pathlib import Path
import httpx
from ..core import *

@app.get("/api/setup/status")
async def setup_status():
    return {"required": setup_required(), "version": APP_VERSION, "language": setting_get("language","cs")}

@app.post("/api/setup")
async def first_setup(request: Request):
    if not setup_required():
        raise HTTPException(409, "Initial setup is already complete")
    p = await request.json()
    username = str(p.get("username") or "admin").strip()
    password = str(p.get("password") or "")
    portainer_url = str(p.get("portainer_url") or "").strip().rstrip("/")
    portainer_token = str(p.get("portainer_token") or "").strip()
    if bool(portainer_url) != bool(portainer_token):
        raise HTTPException(400, "Portainer URL a API token musí být vyplněny společně, nebo oba prázdné.")
    try:
        create_admin(username, password)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if portainer_url and portainer_token:
        setting_set("portainer_url", portainer_url)
        setting_set("portainer_token", portainer_token, True)
    setting_set("vas_hosting_api_key", str(p.get("vas_hosting_api_key") or "").strip(), True)
    setting_set("vas_hosting_api_url", str(p.get("vas_hosting_api_url") or "https://portal.vas-hosting.cz/api/v1").strip())
    setting_set("language", "en" if str(p.get("language") or "cs").lower()=="en" else "cs")
    return {"ok": True, "restart_required": False}

@app.get("/api/app-settings")
async def app_settings(session=Depends(require_permission("admin"))):
    return {
        "portainer_url": setting_get("portainer_url", PORTAINER_URL),
        "portainer_token_set": bool(setting_get("portainer_token", PORTAINER_TOKEN)),
        "vas_hosting_api_key_set": bool(setting_get("vas_hosting_api_key", VAS_HOSTING_API_KEY)),
        "vas_hosting_api_url": setting_get("vas_hosting_api_url", VAS_HOSTING_API_URL),
        "language": setting_get("language","cs")
    }

@app.put("/api/app-settings")
async def app_settings_save(request: Request, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    p = await request.json()
    if "portainer_url" in p: setting_set("portainer_url", str(p["portainer_url"]).strip().rstrip("/"))
    if p.get("portainer_token"): setting_set("portainer_token", str(p["portainer_token"]).strip(), True)
    if p.get("vas_hosting_api_key"): setting_set("vas_hosting_api_key", str(p["vas_hosting_api_key"]).strip(), True)
    if "vas_hosting_api_url" in p: setting_set("vas_hosting_api_url", str(p["vas_hosting_api_url"]).strip().rstrip("/"))
    if "language" in p: setting_set("language", "en" if str(p["language"]).lower()=="en" else "cs")
    return {"ok": True, "restart_required": False}

@app.put("/api/account/password")
async def account_password(request: Request, session=Depends(require_csrf)):
    p = await request.json()
    current = str(p.get("current_password") or "")
    new = str(p.get("new_password") or "")
    username = session["user"]
    if not authenticate(username, current):
        raise HTTPException(403, "Current password is incorrect")
    if len(new) < 10:
        raise HTTPException(400, "New password must have at least 10 characters")
    with db() as conn:
        conn.execute("UPDATE app_users SET password_hash=?, updated_at=? WHERE username=?", (password_hash(new), utcnow(), username))
    return {"ok": True}


@app.get("/api/update/status")
async def update_status(session=Depends(require_permission("admin"))):
    result_path = "/host-requests/update-result"
    helper_available = os.path.exists("/host-tools/update-dsm")
    result = ""
    try:
        if os.path.exists(result_path):
            result = Path(result_path).read_text(encoding="utf-8").strip()
    except Exception:
        pass
    latest_version = ""
    check_error = ""
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            response = await client.get(
                "https://raw.githubusercontent.com/Drbanek/DockerStackMover/main/app/core.py",
                params={"_": str(int(datetime.now(timezone.utc).timestamp()))},
                headers={"Accept": "text/plain", "Cache-Control": "no-cache", "User-Agent": "DockerStackMover/" + APP_VERSION},
            )
            response.raise_for_status()
            match = re.search(r'^APP_VERSION\s*=\s*["\']([^"\']+)["\']', response.text, re.MULTILINE)
            if not match:
                raise RuntimeError("Verze nebyla v main nalezena")
            latest_version = match.group(1)
    except Exception as exc:
        check_error = str(exc)
    return {
        "helper_available": helper_available,
        "result": result,
        "version": APP_VERSION,
        "latest_version": latest_version,
        "update_available": bool(latest_version and tuple(int(x) for x in latest_version.split(".")) > tuple(int(x) for x in APP_VERSION.split("."))),
        "check_error": check_error,
    }

@app.post("/api/update")
async def update_dsm(session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")):
        raise HTTPException(403, "Permission denied")
    if not os.path.exists("/host-tools/update-dsm"):
        raise HTTPException(409, "Host update helper není nainstalován. Spusť jednou aktuální install.sh na MGMT.")
    req = Path("/host-requests/update-request")
    result = Path("/host-requests/update-result")
    try:
        result.unlink(missing_ok=True)
        tmp = Path("/host-requests/update-request.tmp")
        tmp.write_text("UPDATE\n", encoding="utf-8")
        tmp.replace(req)
    except Exception as exc:
        raise HTTPException(500, "Nelze předat požadavek hostu: " + str(exc))
    return {"ok": True, "message": "Aktualizace byla předána hostu. DSM se během aktualizace restartuje."}
