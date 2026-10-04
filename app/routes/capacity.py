from ..core import *
from .general import stack_detail



def endpoint_host_ip(endpoint):
    """Resolve a usable node IP. Explicit Host IP is an override; otherwise derive it from Portainer."""
    eid = int(endpoint.get("Id"))
    configured = (get_endpoint_settings().get(eid, {}).get("host_ip") or "").strip()
    if configured:
        return configured, "configured"
    candidates = [
        endpoint.get("URL"), endpoint.get("Url"),
        endpoint.get("PublicURL"), endpoint.get("PublicUrl"),
        endpoint.get("EdgeCheckinInterval")
    ]
    for value in candidates:
        if not isinstance(value, str) or not value.strip():
            continue
        value = value.strip()
        try:
            from urllib.parse import urlparse
            parsed = urlparse(value if "://" in value else "//" + value)
            host = parsed.hostname
            if host:
                import ipaddress
                ipaddress.ip_address(host)
                return host, "portainer"
        except Exception:
            pass
    return "", ""

CAPACITY_AGENT_IMAGE = os.getenv("CAPACITY_AGENT_IMAGE", "ghcr.io/drbanek/dockerstackmover-capacity-agent:latest")
CAPACITY_AGENT_CONTAINER = "dockerstackmover-capacity-agent"


async def ensure_mgmt_wireguard():
    """DSM 2.1: CONTROL/MGMT is the WireGuard HUB at 10.200.0.1."""
    hub_pub = (setting_get("wg_hub_public_key", "") or "").strip()
    hub_endpoint = (setting_get("wg_hub_endpoint", "") or "").strip()
    if not hub_pub or not hub_endpoint:
        raise RuntimeError("CONTROL WireGuard HUB není nakonfigurovaný.")
    return


async def _agent_container(endpoint_id):
    r = await docker_request(endpoint_id, "GET", "/containers/" + CAPACITY_AGENT_CONTAINER + "/json")
    return r.json() if r.status_code == 200 else None

@app.post("/api/endpoints/{endpoint_id}/capacity-agent/install")
async def install_capacity_agent(endpoint_id: int, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user", "")):
        raise HTTPException(403, "Permission denied")
    endpoints = await get_endpoints()
    endpoint = next((e for e in endpoints if int(e.get("Id")) == endpoint_id), None)
    if not endpoint:
        raise HTTPException(404, "Endpoint not found")
    settings = get_endpoint_settings().get(endpoint_id, {})
    role = settings.get("role","NODE").upper()
    host_ip, host_ip_source = endpoint_host_ip(endpoint)
    if not host_ip:
        raise HTTPException(400, "Host IP se nepodařilo zjistit z Portainer endpointu. Nastav ji ručně v Endpoint settings.")
    token = secrets.token_hex(32)
    # Pull the centrally published agent image through Portainer.
    await ensure_image(endpoint_id, CAPACITY_AGENT_IMAGE)
    existing = await _agent_container(endpoint_id)
    if existing:
        await remove_container(endpoint_id, CAPACITY_AGENT_CONTAINER)
    create = await docker_request(endpoint_id, "POST", "/containers/create",
        params={"name": CAPACITY_AGENT_CONTAINER},
        json={
            "Image": CAPACITY_AGENT_IMAGE,
            "Env": ["AGENT_TOKEN=" + token],
            "ExposedPorts": {"9100/tcp": {}},
            "HostConfig": {
                "Binds": ["/srv:/host/srv:ro", "/var/lib/docker:/host/docker:ro"],
                
                "ReadonlyRootfs": True,
                "Tmpfs": {"/tmp": "rw,noexec,nosuid,size=16m"},
                "SecurityOpt": ["no-new-privileges:true"],
                "CapDrop": ["ALL"],
                "CapAdd": ["NET_ADMIN"],
                "NetworkMode": "host",
                "PidMode": "host",
                "Privileged": False,
                "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0}
            }
        })
    if create.status_code != 201:
        raise HTTPException(create.status_code, "Capacity Agent create failed: " + create.text)
    container_id = create.json()["Id"]
    start = await docker_request(endpoint_id, "POST", "/containers/" + container_id + "/start", json={})
    if start.status_code not in (204, 304):
        await remove_container(endpoint_id, container_id)
        raise HTTPException(start.status_code, "Capacity Agent start failed: " + start.text)
    # Keep an explicitly configured Agent URL; otherwise use the resolved management host.
    agent_url = (settings.get("agent_url") or "").strip().rstrip("/") or ("http://" + host_ip + ":9100")
    last_error = ""
    for _ in range(15):
        try:
            async with httpx.AsyncClient(timeout=3) as hc:
                health = await hc.get(agent_url + "/health")
                capacity = await hc.get(agent_url + "/capacity", headers={"X-Agent-Token": token})
            if health.status_code == 200 and capacity.status_code == 200:
                payload = capacity.json()
                if int((payload.get("data") or {}).get("total") or 0) > 0 and int((payload.get("system") or {}).get("total") or 0) > 0:
                    save_endpoint_setting(endpoint_id, bool(settings.get("migration_enabled")), host_ip,
                        settings.get("site", ""), settings.get("public_ip", ""), agent_url, token, settings.get("role","NODE"))
                    return {"ok": True, "agent_url": agent_url, "image": CAPACITY_AGENT_IMAGE, "host_ip": host_ip, "host_ip_source": host_ip_source}
            last_error = "health=" + str(health.status_code) + ", capacity=" + str(capacity.status_code)
        except Exception as exc:
            last_error = str(exc)
        await asyncio.sleep(1)
    await remove_container(endpoint_id, container_id)
    raise HTTPException(502, "Capacity Agent se po instalaci nepodařilo ověřit: " + last_error)



async def agent_firewall(endpoint_id, method="GET", payload=None, suffix=""):
    settings=get_endpoint_settings().get(int(endpoint_id),{}); url=(settings.get("agent_url") or "").rstrip("/"); token=settings.get("agent_token") or ""
    if not url or not token: raise RuntimeError("Node Agent is not configured")
    async with httpx.AsyncClient(timeout=8) as hc:
        r=await hc.request(method,url+"/firewall"+suffix,headers={"X-Agent-Token":token},json=payload)
    if r.status_code != 200: raise RuntimeError("Firewall Agent HTTP "+str(r.status_code)+": "+r.text[:300])
    return r.json()

@app.get("/api/endpoints/{endpoint_id}/firewall")
async def firewall_status(endpoint_id:int,session=Depends(require_permission("admin"))):
    return await agent_firewall(endpoint_id)

@app.put("/api/endpoints/{endpoint_id}/firewall")
async def firewall_apply(endpoint_id:int,request:Request,session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    p=await request.json(); sources=[str(x).strip() for x in p.get("management_sources",[]) if str(x).strip()]
    ports=p.get("management_ports") or [9001,9100]
    timeout=max(30,min(int(p.get("confirm_timeout") or 90),300))
    result=await agent_firewall(endpoint_id,"PUT",{"management_sources":sources,"management_ports":ports,"confirm_timeout":timeout})
    txid=result.get("transaction_id")
    if not txid: return result
    # Verify through the same central path that will manage this node. If the
    # agent cannot be reached after applying the rules, do not confirm it.
    await asyncio.sleep(1)
    verify=await agent_firewall(endpoint_id)
    result["verified_after_apply"]=True
    return result

@app.post("/api/endpoints/{endpoint_id}/firewall/confirm/{txid}")
async def firewall_confirm(endpoint_id:int,txid:str,session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    return await agent_firewall(endpoint_id,"POST",suffix="/confirm/"+txid)

@app.post("/api/endpoints/{endpoint_id}/firewall/rollback/{txid}")
async def firewall_rollback(endpoint_id:int,txid:str,session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    return await agent_firewall(endpoint_id,"POST",suffix="/rollback/"+txid)

async def node_readiness(endpoint):
    """Return an actionable readiness report for any Portainer endpoint."""
    endpoint_id = int(endpoint["Id"])
    settings = get_endpoint_settings().get(endpoint_id, {})
    role = (settings.get("role") or "NONE").upper()
    host_ip, host_ip_source = endpoint_host_ip(endpoint)
    if role in ("PORTAINER","CONTROL","MGMT") and not host_ip:
        host_ip = (setting_get("wg_hub_lan_ip", "") or "").strip() or "10.200.0.1"
        host_ip_source = "wg_hub"
    checks = {
        "docker": {"ok": False, "message": "Docker API unavailable"},
        "host_ip": {"ok": bool(host_ip), "message": host_ip or "Host IP could not be detected"},
        "capacity_agent": {"ok": False, "message": "Not configured"},
        "data_disk": {"ok": False, "message": "/srv capacity unavailable"},
        "migration": {"ok": bool(settings.get("migration_enabled")), "message": "Enabled" if settings.get("migration_enabled") else "Disabled"},
        "firewall": {"ok": False, "message": "Not verified"},
        "proxy": {"ok": False, "message": "Traefik not verified"},
    }
    try:
        info = await docker_request(endpoint_id, "GET", "/info")
        checks["docker"] = {"ok": info.status_code == 200, "message": "Online" if info.status_code == 200 else "HTTP " + str(info.status_code)}
    except Exception as exc:
        checks["docker"]["message"] = str(exc)
    if role == "PROXY":
        try:
            traefik = await docker_request(endpoint_id, "GET", "/containers/traefik/json")
            if traefik.status_code == 200:
                state = (traefik.json().get("State") or {})
                running = bool(state.get("Running"))
                checks["proxy"] = {"ok": running, "message": "Traefik running" if running else "Traefik container is not running"}
            else:
                checks["proxy"] = {"ok": False, "message": "Traefik container not found"}
        except Exception as exc:
            checks["proxy"] = {"ok": False, "message": str(exc)}
    if settings.get("agent_url") and settings.get("agent_token"):
        try:
            data_disk, system_disk = await agent_disk_usage(endpoint_id)
            checks["capacity_agent"] = {"ok": True, "message": "Online"}
            checks["data_disk"] = {"ok": True, "message": fmt_bytes(data_disk["free"]) + " free", "free": data_disk["free"], "total": data_disk["total"]}
        except Exception as exc:
            checks["capacity_agent"] = {"ok": False, "message": str(exc)}
        try:
            fw=await agent_firewall(endpoint_id); checks["firewall"]={"ok":bool(fw.get("managed")),"message":"Managed by DockerStackMover" if fw.get("managed") else "Not managed"}
        except Exception as exc: checks["firewall"]={"ok":False,"message":str(exc)}
    if role == "NODE":
        required = ("docker","host_ip","capacity_agent","data_disk","migration","firewall")
    elif role == "PROXY":
        required = ("docker","host_ip","proxy")
    elif role == "PORTAINER":
        required = ("docker","host_ip")
    else:
        required = ("docker","host_ip")
    ready = all(checks[k]["ok"] for k in required)
    return {"id": endpoint_id, "name": endpoint.get("Name") or ("Endpoint " + str(endpoint_id)), "ready": ready,
            "status": "ready" if ready else "setup_required", "host_ip": host_ip, "host_ip_source": host_ip_source,
            "site": settings.get("site", ""), "public_ip": settings.get("public_ip", ""), "role": role, "checks": checks, "required_checks": list(required)}

@app.get("/api/nodes/readiness")
async def nodes_readiness(session=Depends(require_permission("dashboard_read"))):
    endpoints = await get_endpoints()
    result = []
    settings_map = get_endpoint_settings()
    for endpoint in endpoints:
        if (settings_map.get(int(endpoint.get("Id")), {}).get("role") or "NONE").upper() == "NONE":
            continue
        try:
            result.append(await node_readiness(endpoint))
        except Exception as exc:
            result.append({"id": endpoint.get("Id"), "name": endpoint.get("Name"), "ready": False, "status": "error", "error": str(exc)})
    return {"nodes": result}


@app.post("/api/endpoints/{endpoint_id}/prepare/stream")
async def prepare_node_stream(endpoint_id: int, session=Depends(require_csrf)):
    """Prepare a NODE and stream individual readiness steps to the UI."""
    if "admin" not in user_permissions(session.get("user", "")):
        raise HTTPException(403, "Permission denied")

    async def events():
        def ev(step, status, detail=""):
            return json.dumps({"type":"progress","step":step,"status":status,"detail":detail},ensure_ascii=False)+"\n"
        try:
            yield ev("endpoint","running","Načítám endpoint a jeho nastavení…")
            endpoints = await get_endpoints()
            endpoint = next((e for e in endpoints if int(e.get("Id")) == endpoint_id), None)
            if not endpoint:
                yield ev("endpoint","error","Endpoint nebyl nalezen."); return
            settings = get_endpoint_settings().get(endpoint_id, {})
            host_ip, source = endpoint_host_ip(endpoint)
            if not host_ip:
                yield ev("endpoint","error","Host IP se nepodařilo zjistit."); return
            yield ev("endpoint","done","Endpoint OK · "+host_ip)

            yield ev("mgmt_wireguard","running","Ověřuji CONTROL WireGuard HUB 10.200.0.1…")
            await ensure_mgmt_wireguard()
            yield ev("mgmt_wireguard","done","CONTROL WireGuard HUB 10.200.0.1 připraven")

            yield ev("migration","running","Povoluji endpoint pro migrace…")
            save_endpoint_setting(endpoint_id, True, settings.get("host_ip", ""), settings.get("site", ""),
                                  settings.get("public_ip", ""), settings.get("agent_url", ""), None, settings.get("role","NODE"))
            yield ev("migration","done","Migrace povoleny")

            yield ev("image","running","Stahuji/ověřuji image Capacity Agentu…")
            await ensure_image(endpoint_id, CAPACITY_AGENT_IMAGE)
            yield ev("image","done","Capacity Agent image připraven")

            yield ev("container","running","Vytvářím Capacity Agent kontejner…")
            existing = await _agent_container(endpoint_id)
            if existing:
                await remove_container(endpoint_id, CAPACITY_AGENT_CONTAINER)
            token = secrets.token_hex(32)
            create = await docker_request(endpoint_id, "POST", "/containers/create",
                params={"name": CAPACITY_AGENT_CONTAINER},
                json={"Image": CAPACITY_AGENT_IMAGE,"Env":["AGENT_TOKEN="+token],"ExposedPorts":{"9100/tcp":{}},
                      "HostConfig":{"Binds":["/srv:/host/srv:ro","/var/lib/docker:/host/docker:ro"],
                      "ReadonlyRootfs":True,"Tmpfs":{"/tmp":"rw,noexec,nosuid,size=16m"},
                      "SecurityOpt":["no-new-privileges:true"],"CapDrop":["ALL"],"CapAdd":["NET_ADMIN"],
                      "NetworkMode":"host","PidMode":"host","Privileged":False,
                      "RestartPolicy":{"Name":"unless-stopped","MaximumRetryCount":0}}})
            if create.status_code != 201:
                yield ev("container","error","Capacity Agent create failed: "+create.text); return
            container_id=create.json()["Id"]
            start=await docker_request(endpoint_id,"POST","/containers/"+container_id+"/start",json={})
            if start.status_code not in (204,304):
                await remove_container(endpoint_id,container_id)
                yield ev("container","error","Capacity Agent start failed: "+start.text); return

            # Do not claim success only because Docker accepted /start. Verify that
            # the container is actually still running; otherwise surface its state
            # and logs instead of waiting on port 9100 and deleting the evidence.
            await asyncio.sleep(1)
            inspect = await docker_request(endpoint_id, "GET", "/containers/" + container_id + "/json")
            if inspect.status_code != 200:
                yield ev("container","error","Capacity Agent po spuštění nelze ověřit: HTTP "+str(inspect.status_code)+" "+inspect.text[:300]); return
            state = inspect.json().get("State") or {}
            if not state.get("Running"):
                logs = await docker_request(endpoint_id, "GET", "/containers/" + container_id + "/logs",
                                            params={"stdout":"1","stderr":"1","tail":"40"})
                detail = (logs.text if logs.status_code == 200 else "").strip()
                error = (state.get("Error") or "").strip()
                exit_code = state.get("ExitCode")
                message = "Capacity Agent se ihned ukončil (exit "+str(exit_code)+")"
                if error:
                    message += ": "+error
                if detail:
                    message += " · log: "+detail[-1200:]
                yield ev("container","error",message); return
            yield ev("container","done","Capacity Agent běží")

            agent_url=(settings.get("agent_url") or "").strip().rstrip("/") or ("http://"+host_ip+":9100")
            yield ev("health","running","Čekám na "+agent_url+"/health…")
            last_error=""
            verified=False
            for _ in range(15):
                try:
                    async with httpx.AsyncClient(timeout=3) as hc:
                        health=await hc.get(agent_url+"/health")
                        capacity=await hc.get(agent_url+"/capacity",headers={"X-Agent-Token":token})
                    if health.status_code==200 and capacity.status_code==200:
                        payload=capacity.json()
                        if int((payload.get("data") or {}).get("total") or 0)>0 and int((payload.get("system") or {}).get("total") or 0)>0:
                            verified=True; break
                    last_error="health="+str(health.status_code)+", capacity="+str(capacity.status_code)
                except Exception as exc:
                    last_error=str(exc)
                await asyncio.sleep(1)
            if not verified:
                # Keep the failed agent container for diagnostics. Removing it here
                # destroys its state/logs and hides whether :9100 was listening.
                inspect = await docker_request(endpoint_id, "GET", "/containers/" + container_id + "/json")
                diag = ""
                if inspect.status_code == 200:
                    state = inspect.json().get("State") or {}
                    diag = " · container running=" + str(bool(state.get("Running"))).lower()
                    if state.get("Error"):
                        diag += " · error=" + str(state.get("Error"))[:300]
                yield ev("health","error","Capacity Agent se nepodařilo ověřit: "+last_error+diag+" · kontejner ponechán pro diagnostiku"); return
            save_endpoint_setting(endpoint_id, True, host_ip, settings.get("site",""), settings.get("public_ip",""),
                                  agent_url, token, settings.get("role","NODE"))
            yield ev("health","done","Capacity Agent odpovídá na 9100")

            yield ev("disk","running","Ověřuji DATA /srv a systémový disk…")
            data_disk, system_disk = await agent_disk_usage(endpoint_id)
            yield ev("disk","done","DATA /srv: "+fmt_bytes(data_disk["free"])+" volno")

            yield ev("firewall","running","Nastavuji management firewall přes Node Agent…")
            try:
                fw=await agent_firewall(endpoint_id)
                if not fw.get("managed"):
                    # Portainer Agent is managed from MAIN .8; Capacity Agent from DockerStackMover .10.
                    applied=await agent_firewall(endpoint_id,"PUT",{
                        "management_sources":["10.200.0.1"],
                        "management_ports":[9001,9100],
                        "confirm_timeout":90
                    })
                    txid=applied.get("transaction_id")
                    await asyncio.sleep(1)
                    # Critical safety check: this request itself traverses CONTROL 10.200.0.1 -> :9100.
                    verify=await agent_firewall(endpoint_id)
                    if not verify.get("managed"):
                        raise RuntimeError("Firewall pravidla byla aplikována, ale agent je nehlásí jako spravovaná.")
                    if txid:
                        confirmed=await agent_firewall(endpoint_id,"POST",suffix="/confirm/"+txid)
                    fw=await agent_firewall(endpoint_id)
                if fw.get("managed"):
                    yield ev("firewall","done","Management firewall nastaven a ověřen")
                else:
                    yield ev("firewall","error","Firewall se nepodařilo převzít pod správu DockerStackMoveru"); return
            except Exception as exc:
                yield ev("firewall","error",str(exc)); return

            readiness=await node_readiness(endpoint)
            if not readiness.get("ready"):
                yield json.dumps({"type":"error","detail":"NODE po přípravě stále nesplňuje všechny readiness kontroly.","result":readiness},ensure_ascii=False)+"\n"; return
            yield json.dumps({"type":"result","result":readiness},ensure_ascii=False)+"\n"
        except Exception as exc:
            yield json.dumps({"type":"error","detail":"Příprava NODE selhala: "+str(exc)},ensure_ascii=False)+"\n"
    from fastapi.responses import StreamingResponse
    return StreamingResponse(events(),media_type="application/x-ndjson",headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.post("/api/endpoints/{endpoint_id}/prepare")
async def prepare_node(endpoint_id: int, session=Depends(require_csrf)):
    """Enable migrations and install/repair the Capacity Agent in one action."""
    if "admin" not in user_permissions(session.get("user", "")):
        raise HTTPException(403, "Permission denied")
    endpoints = await get_endpoints()
    endpoint = next((e for e in endpoints if int(e.get("Id")) == endpoint_id), None)
    if not endpoint:
        raise HTTPException(404, "Endpoint not found")
    settings = get_endpoint_settings().get(endpoint_id, {})
    host_ip, _ = endpoint_host_ip(endpoint)
    if not host_ip:
        raise HTTPException(400, "Host IP se nepodařilo automaticky zjistit. Nastav ji ručně jako override.")
    save_endpoint_setting(endpoint_id, True, settings.get("host_ip", ""), settings.get("site", ""),
                          settings.get("public_ip", ""), settings.get("agent_url", ""), None, settings.get("role","NODE"))
    # Reuse the hardened installer; it persists generated credentials only after verification.
    await install_capacity_agent(endpoint_id, session)
    return await node_readiness(endpoint)

def fmt_bytes(value):
    value = float(value or 0); units = ["B", "KB", "MB", "GB", "TB"]
    for unit in units:
        if value < 1024 or unit == units[-1]: return f"{value:.1f} {unit}"
        value /= 1024

async def agent_disk_usage(endpoint_id):
    settings = get_endpoint_settings().get(int(endpoint_id), {})
    agent_url = (settings.get("agent_url") or "").strip().rstrip("/")
    token = settings.get("agent_token") or ""
    if not agent_url:
        raise RuntimeError("Capacity Agent není pro endpoint nastaven")
    if not token:
        raise RuntimeError("Capacity Agent token není pro endpoint nastaven")
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(agent_url + "/capacity", headers={"X-Agent-Token": token})
    except Exception as exc:
        raise RuntimeError("Capacity Agent nedostupný: " + str(exc))
    if r.status_code != 200:
        raise RuntimeError("Capacity Agent HTTP " + str(r.status_code) + ": " + r.text[:200])
    payload = r.json()
    def normalize(name, display_path):
        d = payload.get(name) or {}
        total, used, free = int(d.get("total") or 0), int(d.get("used") or 0), int(d.get("free") or 0)
        if total <= 0:
            raise RuntimeError("Capacity Agent nevrátil platnou kapacitu " + display_path)
        return {"path": display_path, "total": total, "used": used, "free": free, "percent": round(used / total * 100, 1)}
    return normalize("data", "/srv"), normalize("system", "/var/lib/docker")

async def node_capacity(endpoint):
    endpoint_id = endpoint["Id"]; info_r = await docker_request(endpoint_id, "GET", "/info")
    if info_r.status_code != 200: raise RuntimeError("Docker info failed for " + endpoint["Name"] + ": " + info_r.text)
    info = info_r.json(); df_r = await docker_request(endpoint_id, "GET", "/system/df"); df = df_r.json() if df_r.status_code == 200 else {}; total_ram = int(info.get("MemTotal") or 0); cpus = int(info.get("NCPU") or 0)
    containers_r = await docker_request(endpoint_id, "GET", "/containers/json?all=0"); containers = containers_r.json() if containers_r.status_code == 200 else []
    used_ram = 0; cpu_percent_total = 0.0; running = 0
    for container in containers:
        cid = container.get("Id")
        if not cid: continue
        stats_r = await docker_request(endpoint_id, "GET", f"/containers/{cid}/stats?stream=false")
        if stats_r.status_code != 200: continue
        stats = stats_r.json(); mem = stats.get("memory_stats", {}); usage = int(mem.get("usage") or 0); cache = int((mem.get("stats") or {}).get("cache") or 0); used_ram += max(0, usage - cache)
        cpu = stats.get("cpu_stats", {}); precpu = stats.get("precpu_stats", {}); cpu_delta = int((cpu.get("cpu_usage") or {}).get("total_usage") or 0) - int((precpu.get("cpu_usage") or {}).get("total_usage") or 0); system_delta = int(cpu.get("system_cpu_usage") or 0) - int(precpu.get("system_cpu_usage") or 0); online = int(cpu.get("online_cpus") or cpus or 1)
        if cpu_delta > 0 and system_delta > 0: cpu_percent_total += cpu_delta / system_delta * online * 100.0
        running += 1
    available_ram = max(0, total_ram - used_ram); images_size = sum(int(i.get("Size") or 0) for i in (df.get("Images") or [])); volumes_size = 0
    for volume in df.get("Volumes") or []:
        usage = volume.get("UsageData") or {}; size = usage.get("Size")
        if isinstance(size, int) and size > 0: volumes_size += size
    docker_used = images_size + volumes_size
    docker_root = str(info.get("DockerRootDir") or "/var/lib/docker")
    system_disk = data_disk = None
    system_disk_error = data_disk_error = None
    try:
        data_disk, system_disk = await agent_disk_usage(endpoint_id)
    except Exception as exc:
        system_disk_error = data_disk_error = str(exc)
    return {"id": endpoint_id, "name": endpoint["Name"], "cpu_count": cpus, "ram_total": total_ram, "ram_used_containers": used_ram, "ram_available_estimate": available_ram, "running_containers": running, "cpu_percent_containers": round(cpu_percent_total, 1), "docker_images_size": images_size, "docker_volumes_size": volumes_size, "docker_used_estimate": docker_used, "ram_total_human": fmt_bytes(total_ram), "ram_used_human": fmt_bytes(used_ram), "ram_available_human": fmt_bytes(available_ram), "docker_used_human": fmt_bytes(docker_used), "docker_root": docker_root,
        "system_disk": ({**system_disk, "total_human":fmt_bytes(system_disk["total"]), "used_human":fmt_bytes(system_disk["used"]), "free_human":fmt_bytes(system_disk["free"])} if system_disk else None), "system_disk_error":system_disk_error,
        "data_path":"/srv", "data_disk": ({**data_disk, "total_human":fmt_bytes(data_disk["total"]), "used_human":fmt_bytes(data_disk["used"]), "free_human":fmt_bytes(data_disk["free"])} if data_disk else None), "data_disk_error":data_disk_error,
        "disk_total": data_disk["total"] if data_disk else None, "disk_used": data_disk["used"] if data_disk else None, "disk_free": data_disk["free"] if data_disk else None, "disk_percent": data_disk["percent"] if data_disk else None, "disk_total_human":fmt_bytes(data_disk["total"]) if data_disk else None, "disk_used_human":fmt_bytes(data_disk["used"]) if data_disk else None, "disk_free_human":fmt_bytes(data_disk["free"]) if data_disk else None, "disk_error":data_disk_error}

@app.get("/api/cluster")
async def cluster_dashboard(session=Depends(require_permission("dashboard_read"))):
    endpoints = await get_endpoints(); nodes = migration_endpoints(endpoints)
    async with client() as c:
        stacks_r = await c.get("/api/stacks")
        if stacks_r.status_code != 200: raise HTTPException(stacks_r.status_code, "Portainer stacks: " + stacks_r.text)
        stacks = stacks_r.json()
    result = []; dashboard_stacks = []
    for endpoint in nodes:
        endpoint_id = int(endpoint["Id"])
        try: cap = await node_capacity(endpoint)
        except Exception as exc: cap = {"id": endpoint_id, "name": endpoint.get("Name"), "error": str(exc)}
        node_stacks = []
        for stack in stacks:
            if int(stack.get("EndpointId") or 0) != endpoint_id: continue
            stack_id = int(stack.get("Id"))
            item = {"id": stack_id, "name": stack.get("Name"), "status": stack.get("Status"), "endpoint_id": endpoint_id, "endpoint": endpoint.get("Name") or ("Endpoint " + str(endpoint_id)), "domains": [], "size_bytes": 0, "size_human": "0 B"}
            try:
                detail = await build_detail(stack_id)
                item["domains"] = [d.get("host") for d in detail.get("domains", []) if d.get("host")]
                volume_names = {v.get("name") for v in detail.get("volumes", []) if v.get("name")}
                df_r = await docker_request(endpoint_id, "GET", "/system/df")
                if df_r.status_code == 200:
                    df = df_r.json()
                    volume_size = 0
                    for volume in df.get("Volumes") or []:
                        if volume.get("Name") not in volume_names: continue
                        size = (volume.get("UsageData") or {}).get("Size")
                        if isinstance(size, int) and size > 0: volume_size += size
                    image_names = {str(x.get("image") or "") for x in detail.get("containers", [])}
                    image_size = 0
                    for image in df.get("Images") or []:
                        tags = image.get("RepoTags") or []
                        if any(tag in image_names for tag in tags):
                            image_size += int(image.get("Size") or 0)
                    item["size_bytes"] = volume_size + image_size
                    item["size_human"] = fmt_bytes(item["size_bytes"])
            except Exception as exc:
                item["size_error"] = str(exc)
            node_stacks.append({"id": item["id"], "name": item["name"], "status": item["status"], "endpoint_id": endpoint_id})
            dashboard_stacks.append(item)
        cap["stacks"] = sorted(node_stacks, key=lambda s: str(s.get("name", "")).lower()); result.append(cap)
    healthy = [n for n in result if not n.get("error")]; recommended = None
    if healthy: recommended = sorted(healthy, key=lambda n: (-n["ram_available_estimate"], n["cpu_percent_containers"], len(n["stacks"]), n["id"]))[0]["id"]
    dashboard_stacks.sort(key=lambda s: str(s.get("name") or "").lower())
    return {"nodes": result, "stacks": dashboard_stacks, "recommended_endpoint_id": recommended}

@app.get("/api/nodes/capacity")
async def nodes_capacity(session=Depends(require_permission("dashboard_read"))):
    endpoints = await get_endpoints(); nodes = migration_endpoints(endpoints); result = []
    for endpoint in nodes:
        try: result.append(await node_capacity(endpoint))
        except Exception as exc: result.append({"id": endpoint.get("Id"), "name": endpoint.get("Name"), "error": str(exc)})
    healthy = [n for n in result if not n.get("error")]; recommended = None
    if healthy: recommended = sorted(healthy, key=lambda n: (-n["ram_available_estimate"], n["cpu_percent_containers"], n["running_containers"], n["id"]))[0]["id"]
    return {"nodes": result, "recommended_endpoint_id": recommended, "method": "Recommendation uses estimated free RAM from total host RAM minus current container memory usage."}

@app.get("/api/stacks/{stack_id}/advisor")
async def migration_advisor(stack_id: int, session=Depends(require_permission("migrations"))):
    detail = await stack_detail(stack_id); source_id = int(detail["stack"]["endpoint_id"]); endpoints = await get_endpoints(); nodes = [e for e in migration_endpoints(endpoints) if int(e.get("Id")) != source_id]
    source_volume_bytes = 0
    for volume in detail.get("volumes", []):
        size = volume.get("size")
        if isinstance(size, int) and size > 0: source_volume_bytes += size
    candidates = []
    for endpoint in nodes:
        try:
            cap = await node_capacity(endpoint); warnings = []; ram_ratio = cap["ram_available_estimate"] / cap["ram_total"] if cap["ram_total"] else 0
            if ram_ratio < 0.20: warnings.append("Nízká RAM rezerva (<20 %)")
            if cap["cpu_percent_containers"] > 80: warnings.append("Vysoké aktuální CPU zatížení kontejnerů")
            if source_volume_bytes:
                warnings.append("Volume data k přenosu: " + fmt_bytes(source_volume_bytes))
                if cap.get("data_disk") and source_volume_bytes > cap["data_disk"]["free"]: warnings.append("Nedostatek místa na DATA /srv")
            cap["warnings"] = warnings; cap["source_volume_bytes"] = source_volume_bytes; candidates.append(cap)
        except Exception as exc: candidates.append({"id": endpoint.get("Id"), "name": endpoint.get("Name"), "error": str(exc), "warnings": ["Kapacitu cíle se nepodařilo ověřit"]})
    healthy = [c for c in candidates if not c.get("error")]; recommended = None
    if healthy:
        recommended = sorted(healthy, key=lambda n: (1 if "Nedostatek místa na DATA /srv" in n["warnings"] else 0, len([w for w in n["warnings"] if "Nízká RAM" in w or "Vysoké" in w]), -(n.get("data_disk") or {}).get("free",0), -n["ram_available_estimate"], n["cpu_percent_containers"], n["id"]))[0]["id"]
    return {"stack_id": stack_id, "source_endpoint_id": source_id, "source_volume_bytes": source_volume_bytes, "source_volume_human": fmt_bytes(source_volume_bytes), "recommended_endpoint_id": recommended, "candidates": candidates}

@app.get("/api/migrations")
async def migration_history(session=Depends(require_permission("migrations"))): return load_recent_jobs(100)

@app.get("/api/migrations/{job_id}")
async def migration_status(job_id: str, session=Depends(require_permission("migrations"))):
    job = load_job(job_id)
    if not job: raise HTTPException(404, "Migration job not found")
    return job

async def delete_stack(stack_id, endpoint_id):
    async with client() as c:
        r = await c.delete("/api/stacks/" + str(stack_id), params={"endpointId": endpoint_id})
        if r.status_code not in (200, 204): raise RuntimeError("Stack delete failed: " + r.text)

async def delete_volume(endpoint_id, volume_name):
    r = await docker_request(endpoint_id, "DELETE", "/volumes/" + volume_name)
    if r.status_code not in (204, 404): raise RuntimeError("Volume delete failed " + volume_name + ": " + r.text)

@app.post("/api/migrations/{job_id}/confirm")
async def confirm_migration(job_id: str, session=Depends(require_csrf)):
    if "migrations" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    job = load_job(job_id)
    if not job or job.get("status") != "success" or not job.get("result"): raise HTTPException(409, "Migration is not ready for confirmation")
    result = job["result"]
    if result.get("finalized"): return result
    await delete_stack(result["source_stack_id"], result["source_endpoint_id"])
    for volume_name in result.get("source_volumes", []): await delete_volume(result["source_endpoint_id"], volume_name)
    for change in result.get("dns_changes", []):
        if change.get("provider") == "vas-hosting":
            await vas_update_a_record(change["zone"], change["record_id"], change["host"], change["new_content"], change.get("ttl") or 60)
    result["source_state"] = "deleted"; result["finalized"] = "confirmed"; persist_job(job); release_stack_lock(job["stack_id"], job["id"]); return result

@app.post("/api/migrations/{job_id}/rollback")
async def rollback_migration(job_id: str, session=Depends(require_csrf)):
    if "migrations" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    job = load_job(job_id)
    if not job or job.get("status") != "success" or not job.get("result"): raise HTTPException(409, "Migration is not ready for rollback")
    result = job["result"]
    if result.get("finalized"): return result
    await start_stack(result["source_stack_id"], result["source_endpoint_id"])
    await asyncio.sleep(3)
    from .general import build_detail
    from .proxy import sync_stack_proxy, remove_stack_proxy
    source_detail = await build_detail(result["source_stack_id"])
    if source_detail.get("domains"):
        proxy_result = await sync_stack_proxy(source_detail, result["source_endpoint_id"])
        if not proxy_result.get("configured"):
            raise RuntimeError("Rollback proxy restore did not produce a Traefik configuration")
    for change in reversed(result.get("dns_changes", [])):
        if change.get("provider") == "vas-hosting":
            await vas_update_a_record(change["zone"], change["record_id"], change["host"], change["old_content"], change.get("ttl") or 60)
    settings = get_endpoint_settings()
    source_site = (settings.get(int(result["source_endpoint_id"]), {}).get("site") or "").strip().upper()
    target_site = (settings.get(int(result["target_endpoint_id"]), {}).get("site") or "").strip().upper()
    if source_detail.get("domains") and target_site and target_site != source_site:
        await remove_stack_proxy(source_detail["stack"]["name"], target_site)
    await delete_stack(result["target_stack_id"], result["target_endpoint_id"])
    for volume_name in result.get("volumes", []): await delete_volume(result["target_endpoint_id"], volume_name)
    result["source_state"] = "running"; result["finalized"] = "rolled-back"; persist_job(job); release_stack_lock(job["stack_id"], job["id"]); return result

