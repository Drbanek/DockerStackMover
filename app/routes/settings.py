import json
import re
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
        "language": setting_get("language","cs"),
        "management_access_mode": setting_get("management_access_mode","ip"),
        "management_access_sources": setting_get("management_access_sources",""),
        "management_access_countries": setting_get("management_access_countries","CZ")
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
    if "management_access_mode" in p:
        mode=str(p["management_access_mode"]).strip().lower()
        if mode not in ("ip","country","ip_country","any"): raise HTTPException(400,"Neplatný režim management firewallu.")
        setting_set("management_access_mode",mode)
    if "management_access_sources" in p:
        values=[]
        for raw in str(p["management_access_sources"] or "").replace(",", "\n").splitlines():
            raw=raw.strip()
            if not raw: continue
            try: ipaddress.ip_network(raw,strict=False)
            except Exception: raise HTTPException(400,"Neplatná IP/CIDR: "+raw)
            values.append(raw)
        setting_set("management_access_sources","\n".join(values))
    if "management_access_countries" in p:
        countries=sorted({x.strip().upper() for x in re.split(r"[,\s]+",str(p["management_access_countries"] or "")) if x.strip()})
        if any(not re.fullmatch(r"[A-Z]{2}",x) for x in countries): raise HTTPException(400,"Země musí být ISO kód, např. CZ.")
        setting_set("management_access_countries",",".join(countries))
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
        if os.path.exists(result_path): result = Path(result_path).read_text(encoding="utf-8").strip()
    except Exception: pass
    latest_version = ""; check_error = ""
    urls = [
        "https://api.github.com/repos/Drbanek/DockerStackMover/contents/app/core.py?ref=main",
        "https://raw.githubusercontent.com/Drbanek/DockerStackMover/main/app/core.py",
    ]
    for url in urls:
        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
                response = await client.get(url, headers={"Accept":"application/vnd.github.raw+json" if "api.github.com" in url else "text/plain","Cache-Control":"no-cache","User-Agent":"DockerStackMover/"+APP_VERSION})
                response.raise_for_status()
                body=response.text
                if "api.github.com" in url and response.headers.get("content-type","").startswith("application/json"):
                    import base64
                    body=base64.b64decode(response.json().get("content","")).decode("utf-8")
                match=re.search(r'^APP_VERSION\s*=\s*["\']([^"\']+)["\']',body,re.MULTILINE)
                if not match: raise RuntimeError("Verze nebyla v main nalezena")
                latest_version=match.group(1);check_error="";break
        except Exception as exc: check_error=str(exc)
    def ver(v):
        try: return tuple(int(x) for x in str(v).split("."))
        except Exception: return (0,)
    return {"helper_available":helper_available,"result":result,"version":APP_VERSION,"latest_version":latest_version,
            "update_available":bool(latest_version and ver(latest_version)>ver(APP_VERSION)),"check_error":check_error}

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
    return {"ok": True, "message": "Aktualizace byla předána hostu. DSM se během aktualizace restartuje.",
            "current_version": APP_VERSION, "target_version": latest_version if 'latest_version' in locals() else ""}


@app.get("/api/system/public-access")
async def system_public_access_status(session=Depends(require_permission("admin"))):
    return {"enabled": setting_get("dsm_public_enabled", "0") == "1",
            "hostname": setting_get("dsm_public_hostname", "dsm.lukas.cloud"),
            "backend_ip": setting_get("wg_hub_lan_ip", ""),
            "backend_port": int(setting_get("dsm_public_backend_port", "8082") or 8082)}

@app.post("/api/system/public-access")
async def system_public_access_enable(request: Request, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")): raise HTTPException(403, "Permission denied")
    p = await request.json()
    host = str(p.get("hostname") or "dsm.lukas.cloud").strip().lower().rstrip(".")
    port = int(p.get("backend_port") or 8082)
    if not re.fullmatch(r"[a-z0-9.-]+", host) or "." not in host: raise HTTPException(400, "Neplatný DSM hostname.")
    if not (1 <= port <= 65535): raise HTTPException(400, "Neplatný backend port.")
    backend_ip = str(setting_get("wg_hub_lan_ip", "") or "").strip()
    if not backend_ip: raise HTTPException(409, "CONTROL/MGMT LAN IP není známá.")
    main = next((x for x in get_sites() if int(x.get("management_octet") or 0) == 1), None)
    if not main: raise HTTPException(409, "MAIN lokalita nebyla nalezena.")
    anchor = str(main.get("proxy_dns_hostname") or "").strip().lower().rstrip(".")
    if not anchor: raise HTTPException(409, "MAIN lokalita nemá Proxy DNS hostname.")
    from .proxy import _site_proxy, _run_proxy_helper, _write_dynamic_file
    proxy_id = _site_proxy(main["name"])
    await _run_proxy_helper(proxy_id, "nc -z -w 5 " + backend_ip + " " + str(port), host_network=True)
    rule = "Host(" + chr(96) + host + chr(96) + ")"
    config = "\n".join(["http:", "  routers:", "    dsm-system-web:", "      rule: " + json.dumps(rule),
        "      entryPoints: [web]", "      service: dsm-system", "    dsm-system-secure:",
        "      rule: " + json.dumps(rule), "      entryPoints: [websecure]", "      service: dsm-system",
        "      tls:", "        certResolver: " + setting_get("traefik_cert_resolver", "letsencrypt"),
        "  services:", "    dsm-system:", "      loadBalancer:", "        servers:",
        "          - url: " + json.dumps("http://" + backend_ip + ":" + str(port))]) + "\n"
    await _write_dynamic_file(proxy_id, "dsm-system-ui.yml", config)
    zone, records = await vas_find_zone(host)
    cname = [r for r in records if _dns_record_fqdn(r, zone) == host and str(r.get("type") or "").upper() == "CNAME"]
    conflicts = [r for r in records if _dns_record_fqdn(r, zone) == host and str(r.get("type") or "").upper() != "CNAME"]
    if conflicts: raise HTTPException(409, host + " už má jiný DNS záznam; DSM ho nepřepíše.")
    if cname:
        values = {str(r.get("content") or "").rstrip(".").lower() for r in cname}
        if values != {anchor}: raise HTTPException(409, host + " CNAME existuje s jinou hodnotou; DSM ho nepřepíše.")
        record = cname[0]
    else:
        record = await vas_create_record(zone, host, "CNAME", anchor, 60)
    _remember_managed_dns("__DSM_SYSTEM__", None, host, zone, record, anchor, "system")
    setting_set("dsm_public_enabled", "1"); setting_set("dsm_public_hostname", host); setting_set("dsm_public_backend_port", str(port))
    return {"ok": True, "hostname": host, "target": anchor, "backend": backend_ip + ":" + str(port)}
