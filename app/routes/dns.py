from ..core import *

async def _vas_request(method, path, payload=None):
    if not vas_hosting_enabled():
        raise HTTPException(409, "Váš Hosting API není nakonfigurováno")
    api_url, api_key = vas_config()
    async with httpx.AsyncClient(base_url=api_url, headers={"X-API-Key": api_key, "Content-Type": "application/json"}, timeout=30) as c:
        r = await c.request(method, path, json=payload)
        if r.status_code not in (200, 201, 204):
            raise HTTPException(r.status_code, "Váš Hosting API: " + r.text[:500])
        if not r.content:
            return None
        try: return r.json()
        except Exception: return None

@app.get("/api/dns/status")
async def dns_status(session=Depends(require_permission("dns_read"))):
    return {"provider": "vas-hosting", "configured": vas_hosting_enabled()}

@app.get("/api/dns/domains")
async def dns_domains(session=Depends(require_permission("dns_read"))):
    data = await _vas_request("GET", "/domains")
    return [{"name": name, **meta} for name, meta in sorted((data or {}).items())]

@app.get("/api/dns/domains/{zone}/records")
async def dns_records(zone: str, session=Depends(require_permission("dns_read"))):
    return await vas_dns_records(zone)

@app.post("/api/dns/domains/{zone}/records")
async def dns_create(zone: str, request: Request, session=Depends(require_csrf)):
    if "dns_write" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    payload = await request.json()
    allowed = {k: payload.get(k) for k in ("name","content","type","ttl","priority","note","isCloudflareProxy") if k in payload}
    await _vas_request("POST", "/domains/" + zone + "/dns-records", allowed)
    return {"ok": True, "records": await vas_dns_records(zone)}

@app.put("/api/dns/domains/{zone}/records/{record_id}")
async def dns_update(zone: str, record_id: str, request: Request, session=Depends(require_csrf)):
    if "dns_write" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    payload = await request.json()
    allowed = {k: payload.get(k) for k in ("name","content","type","ttl","priority","note","isCloudflareProxy") if k in payload}
    await _vas_request("POST", "/domains/" + zone + "/dns-records/" + record_id, allowed)
    return {"ok": True, "records": await vas_dns_records(zone)}

@app.delete("/api/dns/domains/{zone}/records/{record_id}")
async def dns_delete(zone: str, record_id: str, session=Depends(require_csrf)):
    if "dns_write" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    await _vas_request("DELETE", "/domains/" + zone + "/dns-records/" + record_id)
    return {"ok": True, "records": await vas_dns_records(zone)}


@app.post("/api/dns/sync-routes")
async def dns_sync_routes(session=Depends(require_csrf)):
    if "dns_write" not in user_permissions(session.get("user","")) and "admin" not in user_permissions(session.get("user","")):
        raise HTTPException(403, "Permission denied")
    if not vas_hosting_enabled():
        raise HTTPException(409, "Nejdřív nastav Váš Hosting API.")
    from .general import build_detail
    stacks = await get_stacks()
    settings = get_endpoint_settings()
    results = []
    for stack in stacks:
        detail = await build_detail(int(stack["Id"]))
        endpoint_id = int(detail["stack"]["endpoint_id"])
        site = (settings.get(endpoint_id, {}).get("site") or "").strip().upper()
        for route in get_stack_proxy_routes(detail["stack"]["name"]):
            try:
                dns = await ensure_route_dns(detail["stack"]["name"], route["id"], route["host"], site)
                results.append({"stack": detail["stack"]["name"], "host": route["host"], "ok": True, "dns": dns})
            except Exception as exc:
                results.append({"stack": detail["stack"]["name"], "host": route["host"], "ok": False, "error": str(exc)})
    return {"ok": all(x["ok"] for x in results), "results": results}
