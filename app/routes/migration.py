from ..core import *
from .general import *
from .proxy import sync_stack_proxy, remove_stack_proxy, activate_stack_proxy_tls, verify_stack_proxy_tls

def _resolve_public_a(host, resolver):
    import socket
    import dns.resolver
    query = dns.resolver.Resolver(configure=False)
    query.nameservers = [resolver]
    query.timeout = 2
    query.lifetime = 4
    return sorted({str(answer) for answer in query.resolve(host, "A")})


async def migration_worker(job):
    stack_id = job["stack_id"]; target_id = job["target_id"]; source_stopped = False; created_volumes = []; dns_changes = []; target_proxy_configured = False
    try:
        job["status"] = "running"; persist_job(job); job_step(job, "Příprava", "running", "Načítám zdroj a cíl")
        detail = await build_detail(stack_id); endpoints = await get_endpoints(); stacks = await get_stacks(); source_id = detail["stack"]["endpoint_id"]
        target = next((e for e in endpoints if e["Id"] == target_id), None); source_endpoint = next((e for e in endpoints if e["Id"] == source_id), None); source_stack = next((s for s in stacks if s["Id"] == stack_id), None)
        if not target or not source_endpoint or not source_stack: raise RuntimeError("Source stack or target endpoint not found")
        if source_id == target_id: raise RuntimeError("Source and target are identical")
        if int(target_id) not in {int(e["Id"]) for e in migration_endpoints(endpoints)}: raise RuntimeError("Target endpoint is not enabled for migrations")
        job_step(job, "Příprava", "ok", detail["stack"]["endpoint"] + " → " + target["Name"]); job_step(job, "Kontrola kolizí", "running", "Opakuji bezpečnostní kontroly před změnou")
        if any(s.get("EndpointId") == target_id and s.get("Name") == detail["stack"]["name"] for s in stacks): raise RuntimeError("Target stack already exists")
        for volume in detail["volumes"]:
            r = await docker_request(target_id, "GET", "/volumes/" + volume["name"])
            if r.status_code == 200: raise RuntimeError("Target volume already exists: " + volume["name"])
            if r.status_code != 404: raise RuntimeError("Cannot inspect target volume " + volume["name"] + ": " + r.text)
        target_containers = (await docker_get(target_id, "/containers/json", params={"all": "1"})).json()
        used_ports = {(int(p["PublicPort"]), p.get("Type", "tcp")) for c in target_containers for p in c.get("Ports", []) if p.get("PublicPort")}
        wanted_ports = {(int(p["public"]), p.get("type", "tcp")) for c in detail["containers"] for p in c["ports"] if p.get("public")}
        collision = wanted_ports.intersection(used_ports)
        if collision: raise RuntimeError("Target port collision: " + str(sorted(collision)))
        stack_file = await get_stack_file(stack_id)
        if not stack_file.strip(): raise RuntimeError("Empty stack definition")
        # Managed proxy backends are bound to the WireGuard management IP. Rewrite
        # both LAN/legacy binds and the management bind when moving between NODEs.
        stack_file, source_host_ip, target_host_ip, rewritten_ports = rewrite_host_bind_ip(stack_file, source_endpoint, target)
        source_mgmt = (get_endpoint_settings().get(int(source_id), {}).get("host_ip") or "").strip()
        target_mgmt = (get_endpoint_settings().get(int(target_id), {}).get("host_ip") or "").strip()
        managed_proxy = get_stack_proxy_setting(detail["stack"]["name"])
        if source_mgmt and target_mgmt and source_mgmt != target_mgmt:
            # Rewrite source WireGuard host binds structurally in Compose.
            # Handle both short syntax (IP:HOST:CONTAINER) and long syntax
            # (host_ip/published/target); regex-based rewriting is too fragile.
            import yaml
            compose_data = yaml.safe_load(stack_file) or {}
            for svc in (compose_data.get("services") or {}).values():
                ports = list((svc or {}).get("ports") or [])
                changed_ports = []
                for port in ports:
                    if isinstance(port, str):
                        prefix = source_mgmt + ":"
                        if port.startswith(prefix):
                            port = target_mgmt + port[len(source_mgmt):]
                            rewritten_ports += 1
                    elif isinstance(port, dict):
                        if str(port.get("host_ip") or "").strip() == source_mgmt:
                            port = dict(port)
                            port["host_ip"] = target_mgmt
                            rewritten_ports += 1
                    changed_ports.append(port)
                if ports:
                    svc["ports"] = changed_ports
            stack_file = yaml.safe_dump(compose_data, sort_keys=False, allow_unicode=True)
            if managed_proxy:
                from .proxy import _inject_backend_publish
                service = str(managed_proxy.get("service") or "")
                container_port = int(managed_proxy.get("container_port") or 0)
                backend_port = int(managed_proxy.get("backend_port") or 0)
                if not service or not container_port or not backend_port:
                    raise RuntimeError("Managed proxy metadata nejsou kompletní; migrace byla zastavena před vypnutím zdroje.")
                # Always canonicalize the managed publish. A stale source bind
                # must be removed even when an earlier textual rewrite matched
                # some other occurrence of the source management IP.
                stack_file = _inject_backend_publish(
                    stack_file, service, target_mgmt, backend_port, container_port,
                    replace_managed=True,
                )
                rewritten_ports += 1
        env = source_stack.get("Env") or []
        collision_message = "Cíl je volný"
        if rewritten_ports: collision_message += " · host bind IP: " + source_host_ip + " → " + target_host_ip + " (" + str(rewritten_ports) + "×)"
        job_step(job, "Kontrola kolizí", "ok", collision_message); job_step(job, "Zastavení zdroje", "running", "Zastavuji stack pro konzistentní kopii dat")
        await stop_stack(stack_id, source_id); source_stopped = True; await asyncio.sleep(3); job_step(job, "Zastavení zdroje", "ok", "Zdrojový stack je zastaven")
        volume_sizes = {}
        for volume in detail["volumes"]:
            measured = await volume_size_mb(source_id, volume["name"])
            volume_sizes[volume["name"]] = int(measured or 0)
        total_volume_mb = sum(volume_sizes.values())
        job["volume_sizes_mb"] = volume_sizes
        job["total_volume_mb"] = total_volume_mb
        persist_job(job)
        backup_volumes = []
        if setting_get("migration_backup_enabled", "true").lower() == "true" and detail["volumes"]:
            job_step(job, "Snapshot před migrací", "running", "Vytvářím konzistentní lokální snapshot persistentních volumes · celkem " + str(total_volume_mb) + " MB")
            backup_id = uuid.uuid4().hex[:12]
            for volume in detail["volumes"]:
                backup_name = "dsm-backup-" + backup_id + "-" + volume["name"]
                await create_volume(source_id, backup_name, volume.get("driver") or "local")
                async def snapshot_progress(mb, volume_name=volume["name"]):
                    job_step(job, "Snapshot před migrací", "running", "Lokální snapshot " + volume_name + " · " + str(mb) + " / " + str(volume_sizes.get(volume_name, 0)) + " MB", {"current_mb": mb, "total_mb": volume_sizes.get(volume_name, 0), "progress_kind": "snapshot"})
                copy_info = await copy_volume(source_id, source_id, volume["name"], backup_name, snapshot_progress)
                backup_volumes.append({"source": volume["name"], "backup": backup_name, "transport": copy_info.get("transport","node-local")})
            setting_set("backup:" + backup_id, json.dumps({"id":backup_id,"created_at":utcnow(),"stack":detail["stack"],"volumes":backup_volumes,"domains":detail["domains"],"stack_file":stack_file,"type":"pre-migration-volume-snapshot"}))
            job_step(job, "Snapshot před migrací", "ok", str(len(backup_volumes)) + " volume snapshot(y) vytvořeny lokálně na zdrojovém NODE · " + backup_id)
        for volume in detail["volumes"]:
            step_name = "Volume: " + volume["name"]; job_step(job, step_name, "running", "Vytvářím volume na cíli")
            await create_volume(target_id, volume["name"], volume.get("driver") or "local"); created_volumes.append(volume["name"])
            source_cfg = get_endpoint_settings().get(int(source_id), {}); target_cfg = get_endpoint_settings().get(int(target_id), {})
            same_site = bool(source_cfg.get("site")) and str(source_cfg.get("site")).strip().upper() == str(target_cfg.get("site") or "").strip().upper()
            planned_transport = "LAN NODE → NODE" if same_site else "WireGuard NODE → NODE"
            job_step(job, step_name, "running", "Přímý přenos " + planned_transport + " · 0 / " + str(volume_sizes.get(volume["name"], 0)) + " MB", {"current_mb": 0, "total_mb": volume_sizes.get(volume["name"], 0), "progress_kind": "transfer"})
            async def transfer_progress(mb, current_step=step_name, transport=planned_transport):
                job_step(job, current_step, "running", "Přímý přenos " + transport + " · " + str(mb) + " / " + str(volume_sizes.get(current_step.replace("Volume: ", ""), 0)) + " MB", {"current_mb": mb, "total_mb": volume_sizes.get(current_step.replace("Volume: ", ""), 0), "progress_kind": "transfer"})
            copy_info = await copy_volume(source_id, target_id, volume["name"], progress_callback=transfer_progress)
            final_message = "Data přenesena přímo přes " + str(copy_info.get("transport") or planned_transport)
            current_step = next((s for s in job["steps"] if s["name"] == step_name), None)
            if current_step:
                match = re.search(r"(\d+) MB", current_step.get("message") or "")
                if match:
                    final_message += " · " + match.group(1) + " MB"
            job_step(job, step_name, "ok", final_message)
        # Persist the exact final Compose sent to Portainer. This is intentionally
        # attached to the migration job so failed target deployments can be diagnosed
        # without guessing which transformation produced the final port bindings.
        job["debug_final_compose"] = stack_file
        job["debug_target_endpoint_id"] = target_id
        job["debug_target_host_ip"] = target_mgmt if 'target_mgmt' in locals() else ""
        persist_job(job)
        job_step(job, "Vytvoření stacku", "running", "Vytvářím stack na " + target["Name"] + " · target WG " + (target_mgmt or "?"))
        created = await create_target_stack(target_id, detail["stack"]["name"], stack_file, env); target_stack_id = created.get("Id")
        job_step(job, "Vytvoření stacku", "ok", "Portainer stack ID: " + str(target_stack_id)); job_step(job, "Ověření cíle", "running", "Čekám na spuštění a healthcheck cílových kontejnerů · timeout 120 s")
        deadline = asyncio.get_running_loop().time() + 120; migrated = []; last_state = "Kontejnery zatím nejsou vytvořené"
        while asyncio.get_running_loop().time() < deadline:
            r = await docker_get(target_id, "/containers/json", params={"all": "1"}); migrated = [c for c in r.json() if (c.get("Labels") or {}).get("com.docker.compose.project") == detail["stack"]["name"]]
            if not migrated:
                last_state = "Kontejnery zatím nejsou vytvořené"; job_step(job, "Ověření cíle", "running", last_state); await asyncio.sleep(3); continue
            waiting = []; fatal = []
            for container in migrated:
                name = container.get("Names", ["unknown"])[0].lstrip("/"); state = container.get("State"); status = container.get("Status") or ""
                if state in ("dead", "removing"): fatal.append(name + " (" + state + ")"); continue
                if state == "exited": fatal.append(name + " (" + status + ")"); continue
                if state != "running": waiting.append(name + " (" + str(state) + ")"); continue
                status_lower = status.lower()
                if "health: starting" in status_lower: waiting.append(name + " (health: starting)")
                elif "unhealthy" in status_lower: fatal.append(name + " (unhealthy)")
            if fatal: raise RuntimeError("Target container failure: " + ", ".join(fatal))
            if not waiting:
                job_step(job, "Ověření cíle", "ok", str(len(migrated)) + " kontejner(y) běží a healthcheck je v pořádku"); break
            last_state = "Čekám: " + ", ".join(waiting); job_step(job, "Ověření cíle", "running", last_state); await asyncio.sleep(3)
        else: raise RuntimeError("Target health timeout after 120 s: " + last_state)
        if detail["domains"]:
            job_step(job, "Proxy cutover", "running", "Připravuji Traefik route na cílovém site přes LAN/DATA síť")
            proxy_result = await sync_stack_proxy(detail, target_id)
            target_proxy_configured = bool(proxy_result.get("configured"))
            job_step(job, "Proxy cutover", "ok", "Traefik připraven · backend " + str(proxy_result.get("lan_ip")) + " · " + str(proxy_result.get("domains")) + " domén(a)")
        settings = get_endpoint_settings(); source_public_ip = settings.get(int(source_id), {}).get("public_ip", ""); target_public_ip = settings.get(int(target_id), {}).get("public_ip", "")
        if detail["domains"] and vas_hosting_enabled() and source_public_ip and target_public_ip and source_public_ip != target_public_ip:
            job_step(job, "DNS cutover", "running", "Přepínám A záznamy " + source_public_ip + " → " + target_public_ip)
            for domain in detail["domains"]:
                host = domain.get("host")
                if not host: continue
                zone, record = await vas_find_a_record(host)
                if record.get("content") != source_public_ip:
                    raise RuntimeError("DNS safety check failed for " + host + ": current A record is " + str(record.get("content")) + ", expected " + source_public_ip)
                change = {"provider": "vas-hosting", "zone": zone, "record_id": record["id"], "host": host, "type": "A", "old_content": record.get("content"), "new_content": target_public_ip, "ttl": int(record.get("ttl") or 60)}
                await vas_update_a_record(zone, record["id"], host, target_public_ip, min(change["ttl"], 60)); dns_changes.append(change)
            job_step(job, "DNS cutover", "ok", str(len(dns_changes)) + " A záznam(y) přepnuty na " + target_public_ip + " · TTL do potvrzení max. 60 s")
            job_step(job, "DNS propagace", "running", "Čekám, až veřejné DNS resolvery vrátí " + target_public_ip)
            dns_deadline = asyncio.get_running_loop().time() + 300
            pending_dns = []
            while asyncio.get_running_loop().time() < dns_deadline:
                pending_dns = []
                for domain in detail["domains"]:
                    host = domain.get("host")
                    if not host: continue
                    for resolver in ("1.1.1.1", "8.8.8.8"):
                        try:
                            answers = await asyncio.to_thread(_resolve_public_a, host, resolver)
                        except Exception as exc:
                            pending_dns.append(host + "@" + resolver + "=" + str(exc))
                            continue
                        if target_public_ip not in answers:
                            pending_dns.append(host + "@" + resolver + "=" + (",".join(answers) or "bez A záznamu"))
                if not pending_dns:
                    break
                job_step(job, "DNS propagace", "running", "Čekám: " + " · ".join(pending_dns[:4]))
                await asyncio.sleep(5)
            if pending_dns:
                raise RuntimeError("DNS propagation timeout after 300 s: " + " · ".join(pending_dns[:6]))
            job_step(job, "DNS propagace", "ok", "Cloudflare i Google vrací " + target_public_ip)
            job_step(job, "SSL certifikát", "running", "DNS je na cíli · aktivuji TLS router a čekám na Let's Encrypt")
            await activate_stack_proxy_tls(detail, target_id)
            ssl_result = await verify_stack_proxy_tls(detail, target_id, timeout=120)
            job_step(job, "SSL certifikát", "ok", str(ssl_result.get("domains")) + " domén(a) má platný certifikát pro cílový PROXY")
        elif detail["domains"]:
            reason = "stejná veřejná IP" if source_public_ip and source_public_ip == target_public_ip else "DNS provider/Public IP není nakonfigurován"
            job_step(job, "DNS cutover", "ok", "Beze změny · " + reason)
        job["status"] = "success"; job["result"] = {"stack": detail["stack"]["name"], "source": detail["stack"]["endpoint"], "source_endpoint_id": source_id, "source_stack_id": stack_id, "target": target["Name"], "target_endpoint_id": target_id, "target_stack_id": target_stack_id, "volumes": created_volumes, "source_volumes": [v["name"] for v in detail["volumes"]], "source_state": "stopped-retained", "dns_changes": dns_changes, "backup_volumes": backup_volumes if 'backup_volumes' in locals() else []}; persist_job(job)
    except Exception as exc:
        import traceback
        error_type = type(exc).__name__
        error_text = str(exc).strip()
        error_detail = error_type + (": " + error_text if error_text else ": " + repr(exc))
        error_traceback = traceback.format_exc()
        job["status"] = "rollback"
        job["error"] = error_detail
        # Keep the traceback in the migration result for diagnostics without
        # exposing it in the normal UI. persist_job stores result_json.
        job["result"] = {"diagnostic_traceback": error_traceback}
        persist_job(job)
        for step in reversed(job["steps"]):
            if step["state"] == "running":
                step["state"] = "error"
                step["message"] = error_detail
                break
        if source_stopped:
            job_step(job, "Rollback zdroje", "running", "Migrace selhala, vracím zdroj do provozu")
            try:
                await start_stack(stack_id, source_id); await asyncio.sleep(5)
                settings = get_endpoint_settings()
                source_site = (settings.get(int(source_id), {}).get("site") or "").strip().upper()
                target_site = (settings.get(int(target_id), {}).get("site") or "").strip().upper()
                if detail.get("domains"):
                    proxy_result = await sync_stack_proxy(detail, source_id)
                    if not proxy_result.get("configured"):
                        raise RuntimeError("Rollback proxy restore did not produce a Traefik configuration")
                rollback_errors = []
                # DNS is the traffic switch: restore it first. Cleanup failures must
                # never prevent DNS rollback.
                for change in reversed(dns_changes):
                    try:
                        await vas_update_a_record(change["zone"], change["record_id"], change["host"], change["old_content"], change["ttl"])
                    except Exception as dns_exc:
                        rollback_errors.append("DNS " + change["host"] + ": " + str(dns_exc))
                if target_proxy_configured and target_site and target_site != source_site:
                    try:
                        await remove_stack_proxy(detail["stack"]["name"], target_site)
                    except Exception as proxy_exc:
                        rollback_errors.append("target PROXY cleanup: " + str(proxy_exc))
                if rollback_errors:
                    raise RuntimeError("Rollback částečně selhal: " + " · ".join(rollback_errors))
                job_step(job, "Rollback zdroje", "ok", "Zdrojový stack byl znovu spuštěn" + (" a DNS vráceno" if dns_changes else ""))
            except Exception as rollback_exc: job_step(job, "Rollback zdroje", "error", "Rollback selhal: " + str(rollback_exc))
        job["status"] = "failed"; persist_job(job); release_stack_lock(job["stack_id"], job["id"])

@app.post("/api/stacks/{stack_id}/migrate/{target_id}")
async def migrate(stack_id: int, target_id: int, session=Depends(require_csrf)):
    if "migrations" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    active = next((j for j in load_recent_jobs(100) if j["stack_id"] == stack_id and j["status"] in ("queued", "running", "rollback")), None)
    if active: return {"job_id": active["id"], "status": active["status"]}
    job = new_job(stack_id, target_id); asyncio.create_task(migration_worker(job)); return {"job_id": job["id"], "status": job["status"]}

@app.post("/api/login")
async def login(request: Request):
    payload = await request.json(); user = str(payload.get("username", "")); password = str(payload.get("password", ""))
    if not authenticate(user, password): raise HTTPException(401, "Invalid credentials")
    token, csrf = new_session(); sessions[token]["user"] = user; response = Response(content=json.dumps({"ok": True, "csrf": csrf}), media_type="application/json")
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="strict", secure=False, max_age=28800); return response

@app.post("/api/logout")
async def logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if token: sessions.pop(token, None)
    response = Response(content=json.dumps({"ok": True}), media_type="application/json"); response.delete_cookie(SESSION_COOKIE); return response

@app.get("/api/session")
async def session_info(session=Depends(current_session)): return {"authenticated": True, "user": session["user"], "csrf": session["csrf"], "permissions": sorted(user_permissions(session["user"])), "language": setting_get("language","cs")}
