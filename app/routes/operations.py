from fastapi.responses import StreamingResponse
from ..core import *
from .general import build_detail
from .capacity import node_capacity, node_readiness, CAPACITY_AGENT_IMAGE, _agent_container

async def _stack_preflight(stack_id: int, target_id: int, progress=None):
    detail = await build_detail(stack_id)
    endpoints = await get_endpoints()
    source_id = int(detail["stack"]["endpoint_id"])
    target = next((e for e in endpoints if int(e.get("Id")) == int(target_id)), None)
    if not target: raise HTTPException(404, "Target endpoint not found")
    checks=[]; blocking=False
    if progress is None: progress=lambda *args: None
    def add(name, ok, message, severity="error"):
        nonlocal blocking
        checks.append({"name":name,"ok":bool(ok),"message":message,"severity":severity})
        progress(name, "done" if ok else ("warning" if severity=="warning" else "error"), message)
        if not ok and severity=="error": blocking=True
    progress("source_target","running","Zdroj a cíl…")
    add("source_target", source_id != int(target_id), "Source and target differ")
    progress("target_ready","running","Připravenost cíle…")
    ready = await node_readiness(target)
    add("target_ready", ready.get("ready"), "Target READY" if ready.get("ready") else "Target requires setup")
    progress("stack_name","running","Kolize názvu stacku…")
    stacks=await get_stacks()
    collision=any(int(s.get("EndpointId") or 0)==int(target_id) and s.get("Name")==detail["stack"]["name"] for s in stacks)
    add("stack_name", not collision, "Stack name available" if not collision else "Stack already exists on target")
    progress("ports","running","Kolize portů…")
    target_containers=(await docker_get(target_id,"/containers/json",params={"all":"1"})).json()
    used={(int(p["PublicPort"]),p.get("Type","tcp")) for c in target_containers for p in c.get("Ports",[]) if p.get("PublicPort")}
    wanted={(int(p["public"]),p.get("type","tcp")) for c in detail["containers"] for p in c["ports"] if p.get("public")}
    ports=sorted(wanted.intersection(used)); add("ports",not ports,"No published-port collisions" if not ports else "Port collision: "+str(ports))
    progress("volumes","running","Kolize volumes…")
    existing=[]
    for v in detail["volumes"]:
        r=await docker_request(target_id,"GET","/volumes/"+v["name"])
        if r.status_code==200: existing.append(v["name"])
    add("volumes",not existing,"Volume names available" if not existing else "Existing volumes: "+", ".join(existing))
    progress("bind_mounts","running","Bind mounty…")
    binds=sorted({m.get("source") for c in detail["containers"] for m in c.get("mounts",[]) if m.get("type")=="bind" and m.get("source")})
    add("bind_mounts",not binds,"No host bind mounts" if not binds else "Host bind mounts require manual validation: "+", ".join(binds),"warning")
    progress("proxy_lan_ip","running","Proxy LAN IP…")
    if detail.get("domains"):
        es=get_endpoint_settings(); ts=es.get(int(target_id),{}); site=(ts.get("site") or "").strip().upper(); lan=(ts.get("lan_ip") or "").strip()
        proxies=[s for s in es.values() if (s.get("role") or "").upper()=="PROXY" and (s.get("site") or "").strip().upper()==site]
        add("proxy_lan_ip",bool(lan),"Target LAN IP: "+lan if lan else "Target LAN IP is required for application proxy traffic")
        progress("proxy_site","running","Proxy lokality…")
        proxy_ok = bool(site) and len(proxies)==1
        proxy_message = "Target site must have exactly one PROXY endpoint"
        if proxy_ok:
            proxy_id = next(eid for eid,x in es.items() if (x.get("role") or "").upper()=="PROXY" and (x.get("site") or "").strip().upper()==site)
            proxy_endpoint = next((e for e in endpoints if int(e.get("Id"))==int(proxy_id)), None)
            if proxy_endpoint:
                proxy_ready = await node_readiness(proxy_endpoint)
                proxy_ok = bool(proxy_ready.get("ready"))
                failed = [k+": "+str((proxy_ready.get("checks",{}).get(k) or {}).get("message") or "")
                          for k in proxy_ready.get("required_checks",[]) if not (proxy_ready.get("checks",{}).get(k) or {}).get("ok")]
                proxy_message = "PROXY ready for "+site if proxy_ok else "PROXY not ready: "+" · ".join(failed)
        add("proxy_site",proxy_ok,proxy_message)
    else:
        add("proxy_lan_ip",True,"Stack nemá proxy doménu","warning")
        progress("proxy_site","running","Proxy lokality…")
        add("proxy_site",True,"Stack nemá proxy doménu","warning")
    progress("data_capacity","running","Kapacita DATA /srv…")
    cap=await node_capacity(target)
    add("data_capacity",bool(cap.get("data_disk")),"DATA /srv capacity available" if cap.get("data_disk") else "DATA /srv capacity unavailable")
    images=sorted({c.get("image") for c in detail["containers"] if c.get("image")})
    return {"stack_id":stack_id,"source_endpoint_id":source_id,"target_endpoint_id":target_id,"ready":not blocking,"checks":checks,"images":images,"bind_mounts":binds}

@app.get("/api/stacks/{stack_id}/preflight-v2/{target_id}/stream")
async def preflight_v2_stream(stack_id:int,target_id:int,session=Depends(require_permission("migrations"))):
    q=asyncio.Queue()
    async def worker():
        try:
            def emit(step,status,detail=""): q.put_nowait({"type":"progress","step":step,"status":status,"detail":detail})
            result=await _stack_preflight(stack_id,target_id,emit)
            q.put_nowait({"type":"result","result":result})
        except Exception as exc: q.put_nowait({"type":"error","detail":str(exc)})
        finally: q.put_nowait(None)
    asyncio.create_task(worker())
    async def events():
        while True:
            item=await q.get()
            if item is None: break
            yield json.dumps(item,ensure_ascii=False)+"\\n"
    return StreamingResponse(events(),media_type="application/x-ndjson")

@app.get("/api/stacks/{stack_id}/preflight-v2/{target_id}")
async def preflight_v2(stack_id:int,target_id:int,session=Depends(require_permission("migrations"))):
    return await _stack_preflight(stack_id,target_id)

@app.get("/api/maintenance")
async def maintenance_overview(session=Depends(require_permission("admin"))):
    endpoints=await get_endpoints(); result=[]
    for e in endpoints:
        eid=int(e["Id"])
        try:
            agent=await _agent_container(eid)
            containers=(await docker_get(eid,"/containers/json",params={"all":"1"})).json()
            result.append({"id":eid,"name":e.get("Name"),"docker":True,
                "capacity_agent":{"installed":bool(agent),"image":(agent or {}).get("Config",{}).get("Image"),"state":(agent or {}).get("State",{}).get("Status")},
                "containers":len(containers)})
        except Exception as exc: result.append({"id":eid,"name":e.get("Name"),"docker":False,"error":str(exc)})
    return {"nodes":result,"capacity_agent_image":CAPACITY_AGENT_IMAGE}

@app.post("/api/endpoints/{endpoint_id}/capacity-agent/upgrade")
async def upgrade_capacity_agent(endpoint_id:int,session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    from .capacity import install_capacity_agent
    return await install_capacity_agent(endpoint_id,session)

@app.get("/api/backups")
async def backup_inventory(session=Depends(require_permission("admin"))):
    with db() as conn:
        rows=conn.execute("SELECT key,value,updated_at FROM app_settings WHERE key LIKE 'backup:%' ORDER BY updated_at DESC").fetchall()
    return {"backups":[{"key":r["key"],"value":json.loads(r["value"]),"updated_at":r["updated_at"]} for r in rows]}

@app.post("/api/stacks/{stack_id}/backup")
async def create_stack_backup(stack_id:int,session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")) and "migrations" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    detail=await build_detail(stack_id); stack_file=await get_stack_file(stack_id); endpoint_id=int(detail["stack"]["endpoint_id"])
    backup_id=uuid.uuid4().hex[:12]; copies=[]; stopped=False
    try:
        await stop_stack(stack_id,endpoint_id); stopped=True; await asyncio.sleep(2)
        for volume in detail["volumes"]:
            source=volume["name"]; target="dsm-backup-"+backup_id+"-"+source
            await create_volume(endpoint_id,target,volume.get("driver") or "local")
            await copy_volume(endpoint_id,endpoint_id,source,target); copies.append({"source":source,"backup":target})
    finally:
        if stopped: await start_stack(stack_id,endpoint_id)
    manifest={"id":backup_id,"created_at":utcnow(),"stack":detail["stack"],"volumes":copies,
              "domains":detail["domains"],"stack_file":stack_file,"type":"local-volume-snapshot"}
    setting_set("backup:"+backup_id,json.dumps(manifest))
    return manifest

