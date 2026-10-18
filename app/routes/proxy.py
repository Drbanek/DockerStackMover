import base64
import json
import hashlib
import re
import uuid

from fastapi import Depends, HTTPException

from ..core import *


def _safe_name(value):
    value = re.sub(r"[^a-z0-9-]+", "-", str(value or "").lower()).strip("-")
    return value[:50] or "stack"


def _site_proxy(site):
    site = str(site or "").strip().upper()
    settings = get_endpoint_settings()
    matches = [(eid, s) for eid, s in settings.items()
               if (s.get("role") or "").upper() == "PROXY" and (s.get("site") or "").strip().upper() == site]
    if len(matches) != 1:
        raise RuntimeError("Site " + site + " musí mít právě jeden endpoint s rolí PROXY; nalezeno: " + str(len(matches)))
    return matches[0][0]


async def _run_proxy_helper(proxy_id, cmd, env=None, host_network=False, binds=None):
    """Run a short-lived helper through Portainer's stack API.

    Portainer performs the Docker create/start locally on the endpoint, avoiding
    Docker POST /containers/{id}/start through the reverse proxy.
    """
    name = "dsm-proxy-" + uuid.uuid4().hex[:10]
    environment = {}
    for item in (env or []):
        key, _, value = item.partition("=")
        environment[key] = value
    service = [
        "services:",
        "  helper:",
        "    image: alpine:3.22",
        "    command: [\"sh\", \"-ec\", " + json.dumps(cmd) + "]",
        "    restart: \"no\"",
    ]
    if host_network:
        service.append("    network_mode: host")
    if environment:
        service.append("    environment:")
        for key, value in environment.items():
            service.append("      " + key + ": " + json.dumps(value))
    if binds:
        service.append("    volumes:")
        for bind in binds:
            service.append("      - " + json.dumps(bind))
    stack_file = "\n".join(service) + "\n"
    stack = await create_target_stack(proxy_id, name, stack_file, [])
    stack_id = int(stack.get("Id") or stack.get("id") or 0)
    if not stack_id:
        raise RuntimeError("PROXY helper stack did not return an ID")
    try:
        code = None
        logs_text = ""
        for _ in range(60):
            containers = (await docker_get(proxy_id, "/containers/json", params={"all": "1", "filters": json.dumps({"label": ["com.docker.compose.project=" + name]})})).json()
            if containers:
                state = str(containers[0].get("State") or "").lower()
                status = str(containers[0].get("Status") or "")
                if state == "exited":
                    match = re.search(r"Exited \((\d+)\)", status)
                    code = int(match.group(1)) if match else 1
                    if code != 0:
                        cid = containers[0].get("Id")
                        if cid:
                            logs = await docker_request(proxy_id, "GET", "/containers/" + cid + "/logs", params={"stdout": "1", "stderr": "1"})
                            logs_text = logs.text[-1000:]
                    break
            await asyncio.sleep(0.5)
        if code is None:
            raise RuntimeError("PROXY helper timeout")
        if code != 0:
            raise RuntimeError("PROXY helper failed (" + str(code) + "): " + logs_text)
    finally:
        async with client() as hc:
            await hc.delete("/api/stacks/" + str(stack_id), params={"endpointId": proxy_id})


async def _write_dynamic_file(proxy_id, filename, content):
    if not re.fullmatch(r"[a-z0-9._-]+\.ya?ml", filename):
        raise RuntimeError("Unsafe Traefik filename")
    if not content.strip():
        raise RuntimeError("Refusing to write empty Traefik configuration")
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    expected_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
    tmp = "." + filename + "." + uuid.uuid4().hex[:10] + ".tmp"
    cmd = (
        'umask 022; '
        'printf "%s" ' + json.dumps(encoded) + ' | base64 -d > /dynamic/' + tmp + '; '
        'test -s /dynamic/' + tmp + '; '
        'test "$(sha256sum /dynamic/' + tmp + ' | cut -d" " -f1)" = ' + json.dumps(expected_sha) + '; '
        'mv -f /dynamic/' + tmp + ' /dynamic/' + filename + '; '
        'test -s /dynamic/' + filename + '; '
        'test "$(sha256sum /dynamic/' + filename + ' | cut -d" " -f1)" = ' + json.dumps(expected_sha)
    )
    await _run_proxy_helper(proxy_id, cmd, binds=["/opt/traefik/dynamic:/dynamic"])


async def _remove_dynamic_file(proxy_id, filename):
    if not re.fullmatch(r"[a-z0-9._-]+\.ya?ml", filename):
        raise RuntimeError("Unsafe Traefik filename")
    await _run_proxy_helper(
        proxy_id,
        "rm -f -- /dynamic/" + filename,
        binds=["/opt/traefik/dynamic:/dynamic"],
    )


async def _remove_conflicting_dynamic_files(proxy_id, keep_filename, hosts):
    """Remove stale DSM Traefik files that claim any hostname owned by keep_filename.

    Older DSM versions could leave a previous stack-slug file behind. Traefik then
    loaded both files and two routers claimed the same Host rule. Only DSM-managed
    files are considered; unrelated/manual Traefik configuration is never touched.
    """
    if not re.fullmatch(r"[a-z0-9._-]+\.ya?ml", keep_filename):
        raise RuntimeError("Unsafe Traefik filename")
    clean_hosts = []
    for host in hosts or []:
        host = str(host or "").strip().lower().rstrip(".")
        if not re.fullmatch(r"[a-z0-9.-]+", host) or "." not in host:
            raise RuntimeError("Unsafe Traefik host")
        if host not in clean_hosts:
            clean_hosts.append(host)
    if not clean_hosts:
        return
    patterns = " ".join("-e 'Host(`" + host + "`)' " for host in clean_hosts)
    cmd = (
        'for f in /dynamic/dsm-*.yml /dynamic/dsm-*.yaml; do '
        '[ -f "$f" ] || continue; '
        '[ "$(basename "$f")" = ' + json.dumps(keep_filename) + ' ] && continue; '
        'if grep -Fq ' + patterns + '"$f"; then rm -f -- "$f"; fi; '
        'done'
    )
    await _run_proxy_helper(proxy_id, cmd, binds=["/opt/traefik/dynamic:/dynamic"])


async def sync_stack_proxy(detail, endpoint_id):
    domains = detail.get("domains") or []
    if not domains:
        return {"configured": False, "reason": "no proxy metadata"}
    settings = get_endpoint_settings()
    node = settings.get(int(endpoint_id), {})
    site = (node.get("site") or "").strip().upper()
    lan_ip = (node.get("lan_ip") or "").strip()
    host_ip = (node.get("host_ip") or "").strip()
    if not site:
        raise RuntimeError("Endpoint nemá nastavenou Site / lokalitu")
    stack_name = detail["stack"]["name"]
    managed = any(bool(d.get("managed")) for d in (domains or []))
    backend_ip = host_ip if managed else lan_ip
    if not backend_ip:
        if managed:
            raise RuntimeError("Endpoint nemá management Host IP pro DSM managed proxy backend.")
        raise RuntimeError("Endpoint nemá nastavenou LAN IP.")
    proxy_id = _site_proxy(site)
    base = _safe_name(stack_name)
    routers = []
    services = []
    tested = set()
    for index, domain in enumerate(domains, start=1):
        host = str(domain.get("host") or "").strip().lower().rstrip(".")
        scheme = str(domain.get("scheme") or "http").strip().lower()
        try:
            port = int(domain.get("port"))
        except Exception:
            raise RuntimeError("Neplatný dc1.proxy.port pro " + (host or stack_name))
        if not re.fullmatch(r"[a-z0-9.-]+", host) or "." not in host:
            raise RuntimeError("Neplatný dc1.proxy.host: " + host)
        if scheme not in ("http", "https") or not (1 <= port <= 65535):
            raise RuntimeError("Neplatný proxy backend pro " + host)
        key = (backend_ip, port)
        if key not in tested:
            await _run_proxy_helper(proxy_id, "nc -z -w 5 " + backend_ip + " " + str(port), host_network=True)
            tested.add(key)
        svc = base + "-" + str(index)
        web = svc + "-web"
        secure = svc + "-secure"
        url = scheme + "://" + backend_ip + ":" + str(port)
        routers.extend([
            "    " + web + ":",
            "      rule: " + json.dumps("Host(`" + host + "`)"),
            "      entryPoints: [web]",
            "      service: " + svc,
            "    " + secure + ":",
            "      rule: " + json.dumps("Host(`" + host + "`)"),
            "      entryPoints: [websecure]",
            "      service: " + svc,
            "      tls:",
            "        certResolver: " + setting_get("traefik_cert_resolver", "letsencrypt"),
        ])
        services.extend([
            "    " + svc + ":",
            "      loadBalancer:",
            "        servers:",
            "          - url: " + json.dumps(url),
        ])
    config = "\n".join(["http:", "  routers:"] + routers + ["  services:"] + services) + "\n"
    filename = "dsm-" + base + ".yml"
    await _write_dynamic_file(proxy_id, filename, config)
    # The new complete config is live first; then remove stale DSM files that
    # still claim one of this stack's hostnames. This prevents duplicate Host()
    # routers after stack/domain renames while avoiding a cutover outage.
    await _remove_conflicting_dynamic_files(
        proxy_id,
        filename,
        [str(d.get("host") or "").strip().lower().rstrip(".") for d in domains],
    )
    return {"configured": True, "site": site, "proxy_endpoint_id": proxy_id, "lan_ip": backend_ip, "backend_ip": backend_ip, "file": filename, "domains": len(domains)}


async def activate_stack_proxy_tls(detail, endpoint_id):
    """Reload Traefik only after public DNS points at the target site.

    Rewriting the same dynamic config is not sufficient after a failed ACME
    authorization because Traefik can retain the failed attempt. Restarting the
    target site's Traefik keeps acme.json intact and triggers a clean retry.
    """
    settings = get_endpoint_settings()
    node = settings.get(int(endpoint_id), {})
    site = (node.get("site") or "").strip().upper()
    proxy_id = _site_proxy(site)
    r = await docker_request(proxy_id, "POST", "/containers/traefik/restart", params={"t": 10})
    if r.status_code not in (204, 304):
        raise RuntimeError("Traefik restart failed: HTTP " + str(r.status_code) + " " + r.text[:300])
    deadline = asyncio.get_running_loop().time() + 60
    last = "Traefik se ještě nespustil"
    while asyncio.get_running_loop().time() < deadline:
        state = await docker_request(proxy_id, "GET", "/containers/traefik/json")
        if state.status_code == 200 and (state.json().get("State") or {}).get("Running"):
            return {"ok": True, "proxy_endpoint_id": proxy_id}
        last = "HTTP " + str(state.status_code)
        await asyncio.sleep(2)
    raise RuntimeError("Traefik restart timeout: " + last)


async def verify_stack_proxy_tls(detail, endpoint_id, timeout=120):
    """Verify that the target Traefik serves a certificate valid for every domain."""
    settings = get_endpoint_settings()
    node = settings.get(int(endpoint_id), {})
    site = (node.get("site") or "").strip().upper()
    proxy_id = _site_proxy(site)
    hosts = [str(d.get("host") or "").strip().lower().rstrip(".") for d in (detail.get("domains") or []) if d.get("host")]
    if not hosts:
        return {"ok": True, "domains": 0}
    # The helper shares the PROXY host network, so 127.0.0.1:443 reaches the\n    # local Traefik directly. No PROXY LAN IP, hairpin NAT or DNS is required.\n    # SNI + verify_hostname validates the certificate for the migrated host.
    deadline = asyncio.get_running_loop().time() + timeout
    pending = list(hosts)
    while asyncio.get_running_loop().time() < deadline:
        failed = []
        for host in hosts:
            cmd = (
                'apk add --no-cache openssl >/dev/null 2>&1; '
                'printf "" | openssl s_client -connect 127.0.0.1:443 -servername ' + host +
                ' -verify_hostname ' + host + ' -verify_return_error 2>/dev/null | grep -q "Verify return code: 0 (ok)"'
            )
            try:
                await _run_proxy_helper(proxy_id, cmd, host_network=True)
            except Exception:
                failed.append(host)
        if not failed:
            return {"ok": True, "domains": len(hosts)}
        pending = failed
        await asyncio.sleep(5)
    raise RuntimeError("SSL certificate timeout after " + str(timeout) + " s: " + ", ".join(pending))


async def remove_stack_proxy(stack_name, site):
    if not site:
        return
    proxy_id = _site_proxy(site)
    await _remove_dynamic_file(proxy_id, "dsm-" + _safe_name(stack_name) + ".yml")




def _container_service_name(container):
    labels = container.get("labels") or {}
    return labels.get("com.docker.compose.service") or container.get("name") or ""


def _detect_container_port(container):
    """Pick the only exposed TCP port, preferring HTTP conventions when ambiguous."""
    ports = []
    for p in container.get("ports") or []:
        if p.get("private") and (p.get("type") or "tcp") == "tcp":
            ports.append(int(p["private"]))
    labels = container.get("labels") or {}
    exposed = labels.get("com.docker.compose.container-number")
    unique = sorted(set(ports))
    if len(unique) == 1:
        return unique[0]
    preferred = [p for p in unique if p in (80, 8080, 8000, 3000, 5000)]
    if len(preferred) == 1:
        return preferred[0]
    return None


def _backend_port_for_stack(stack_name, service="", container_port=0):
    # Stable per route target: multiple domains sharing service:port reuse one backend.
    key = str(stack_name) + "|" + str(service) + "|" + str(container_port)
    digest = int(hashlib.sha256(key.encode("utf-8")).hexdigest()[:8], 16)
    return 20000 + (digest % 20000)


def _inject_backend_publish(stack_file, service, host_ip, backend_port, container_port, replace_managed=False):
    """Add a WireGuard-only published port to one compose service.

    During migration, replace any previous DSM-managed binding for the same
    backend/container port so a stale source NODE address cannot survive.
    """
    import yaml
    data = yaml.safe_load(stack_file) or {}
    services = data.get("services") or {}
    if service not in services:
        raise RuntimeError("Služba " + service + " nebyla nalezena v Compose definici.")
    svc = services[service] or {}
    ports = list(svc.get("ports") or [])
    binding = str(host_ip) + ":" + str(backend_port) + ":" + str(container_port)
    if replace_managed:
        suffix = ":" + str(backend_port) + ":" + str(container_port)
        short_suffix = str(backend_port) + ":" + str(container_port)
        cleaned = []
        for item in ports:
            value = str(item)
            if value == short_suffix or value.endswith(suffix):
                continue
            cleaned.append(item)
        ports = cleaned
    if binding not in [str(x) for x in ports]:
        ports.append(binding)
    svc["ports"] = ports
    services[service] = svc
    data["services"] = services
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)


async def _choose_proxy_service(detail):
    candidates = []
    for container in detail.get("containers") or []:
        port = _detect_container_port(container)
        if port:
            candidates.append((_container_service_name(container), port))
    # Only web-facing ports are valid reverse-proxy candidates. Database,
    # cache and other infrastructure ports (e.g. MariaDB 3306) must never make
    # HTTP service auto-detection ambiguous.
    http_ports = {80, 443, 3000, 5000, 8000, 8080, 8081, 8888}
    candidates = [(s,p) for s,p in candidates if s and p in http_ports]
    unique = []
    for item in candidates:
        if item not in unique:
            unique.append(item)
    if len(unique) == 1:
        return unique[0]
    if not unique:
        raise RuntimeError("DSM nedokázal automaticky zjistit HTTP port služby. Služba musí mít právě jeden exposed TCP port (např. nginx 80).")
    raise RuntimeError("Stack má více možných HTTP služeb: " + ", ".join(s + ":" + str(p) for s,p in unique) + ". Automatický výběr není jednoznačný.")


async def _redeploy_stack_with_proxy_port(detail, endpoint_id, service, container_port, backend_port):
    stack_id = int(detail["stack"]["id"])
    stack_file = await get_stack_file(stack_id)
    endpoint = next((e for e in await get_endpoints() if int(e["Id"]) == int(endpoint_id)), None)
    if not endpoint:
        raise RuntimeError("Endpoint nebyl nalezen.")
    host_ip = (get_endpoint_settings().get(int(endpoint_id), {}).get("host_ip") or "").strip()
    if not host_ip:
        raise RuntimeError("Endpoint nemá management Host IP.")
    rewritten = _inject_backend_publish(stack_file, service, host_ip, backend_port, container_port)
    stacks = await get_stacks()
    stack = next((s for s in stacks if int(s.get("Id")) == stack_id), None)
    env = (stack or {}).get("Env") or []
    async with client() as hc:
        resp = await hc.put("/api/stacks/" + str(stack_id), params={"endpointId": int(endpoint_id)},
                            json={"StackFileContent": rewritten, "Env": env, "Prune": False, "PullImage": False}, timeout=120)
    if resp.status_code not in (200, 201):
        raise RuntimeError("Portainer redeploy selhal: HTTP " + str(resp.status_code) + " " + resp.text[:500])
    deadline = asyncio.get_running_loop().time() + 60
    while asyncio.get_running_loop().time() < deadline:
        try:
            await _run_proxy_helper(_site_proxy(get_endpoint_settings()[int(endpoint_id)]["site"]),
                                    "nc -z -w 3 " + host_ip + " " + str(backend_port), host_network=True)
            return
        except Exception:
            await asyncio.sleep(2)
    raise RuntimeError("Backend po redeployi neposlouchá na " + host_ip + ":" + str(backend_port))


@app.get("/api/stacks/{stack_id}/proxy/candidates")
async def proxy_candidates(stack_id: int, session=Depends(require_permission("dashboard_read"))):
    detail = await build_detail(stack_id)
    candidates = []
    seen = set()
    for container in detail.get("containers") or []:
        service = _container_service_name(container)
        for p in container.get("ports") or []:
            port = int(p.get("private") or 0)
            if service and port and (p.get("type") or "tcp") == "tcp" and (service, port) not in seen:
                seen.add((service, port))
                candidates.append({"service": service, "container_port": port, "container": container.get("name")})
    return {"routes": detail.get("domains") or [], "candidates": candidates}


def _legacy_route_target(detail, host):
    host = str(host or "").strip().lower().rstrip(".")
    matches = []
    for container in detail.get("containers") or []:
        labels = container.get("labels") or {}
        if labels.get("dc1.proxy.enable") != "true": continue
        if str(labels.get("dc1.proxy.host") or "").strip().lower().rstrip(".") != host: continue
        service = _container_service_name(container)
        try: legacy_port = int(labels.get("dc1.proxy.port") or 0)
        except Exception: legacy_port = 0
        # Legacy dc1.proxy.port is normally the published host port. Resolve it
        # back to the container's private port; fall back to direct private-port use.
        candidates = []
        for p in container.get("ports") or []:
            if (p.get("type") or "tcp") != "tcp": continue
            private = int(p.get("private") or 0)
            public = int(p.get("public") or 0)
            if legacy_port and (public == legacy_port or private == legacy_port):
                candidates.append(private)
        if not candidates:
            detected = _detect_container_port(container)
            if detected: candidates.append(detected)
        for private in sorted(set(candidates)):
            if service and private: matches.append((service, private, legacy_port))
    unique = []
    for item in matches:
        if item not in unique: unique.append(item)
    if len(unique) != 1:
        raise RuntimeError("DSM nedokázal jednoznačně určit službu pro legacy doménu " + host + ".")
    return unique[0]


@app.post("/api/stacks/{stack_id}/proxy/adopt")
async def proxy_route_adopt(stack_id: int, request: Request, session=Depends(require_csrf)):
    if "migrations" not in user_permissions(session.get("user", "")) and "admin" not in user_permissions(session.get("user", "")):
        raise HTTPException(403, "Permission denied")
    payload = await request.json()
    host = str(payload.get("host") or "").strip().lower().rstrip(".")
    detail = await build_detail(stack_id)
    stack_name = detail["stack"]["name"]
    existing = next((r for r in get_stack_proxy_routes(stack_name) if str(r.get("host") or "").lower() == host), None)
    try:
        service, container_port, legacy_port = _legacy_route_target(detail, host)
        # Adoption must switch to the same DSM-managed backend model used by
        # newly created routes. Keeping a legacy LAN-bound port while marking
        # the route managed makes sync_stack_proxy use host_ip and causes 502.
        backend_port = _backend_port_for_stack(stack_name, service, container_port)
        endpoint_id = int(detail["stack"]["endpoint_id"])
        # Redeploy first and verify the new host_ip backend from PROXY. Until
        # this succeeds the DB/Traefik still describe the working legacy route.
        await _redeploy_stack_with_proxy_port(detail, endpoint_id, service, container_port, backend_port)
        if existing:
            save_stack_proxy_route(stack_name, host, service, container_port, backend_port, True, route_id=existing["id"])
        else:
            save_stack_proxy_route(stack_name, host, service, container_port, backend_port, True)
        refreshed = await build_detail(stack_id)
        result = await sync_stack_proxy(refreshed, endpoint_id)
        return {"ok": True, "host": host, "service": service, "container_port": container_port,
                "backend_port": backend_port, "legacy_port": legacy_port, "proxy": result}
    except HTTPException: raise
    except Exception as exc:
        raise HTTPException(502, "Převzetí legacy směrování selhalo; původní Traefik routa nebyla přepnuta: " + str(exc))


@app.post("/api/stacks/{stack_id}/proxy/routes")
async def proxy_route_create(stack_id: int, request: Request, session=Depends(require_csrf)):
    if "migrations" not in user_permissions(session.get("user", "")) and "admin" not in user_permissions(session.get("user", "")):
        raise HTTPException(403, "Permission denied")
    payload = await request.json()
    host = str(payload.get("host") or "").strip().lower().rstrip(".")
    service = str(payload.get("service") or "").strip()
    try: container_port = int(payload.get("container_port") or 0)
    except Exception: container_port = 0
    if not re.fullmatch(r"[a-z0-9.-]+", host) or "." not in host:
        raise HTTPException(400, "Zadej platnou doménu.")
    detail = await build_detail(stack_id)
    if not service or not (1 <= container_port <= 65535):
        try: service, container_port = await _choose_proxy_service(detail)
        except Exception as exc: raise HTTPException(400, str(exc))
    valid = any(_container_service_name(c) == service and any(int(p.get("private") or 0) == container_port for p in (c.get("ports") or [])) for c in detail.get("containers") or [])
    if not valid:
        raise HTTPException(400, "Služba " + service + ":" + str(container_port) + " nebyla ve stacku nalezena.")
    backend_port = _backend_port_for_stack(detail["stack"]["name"], service, container_port)
    endpoint_id = int(detail["stack"]["endpoint_id"])
    containers = (await docker_get(endpoint_id, "/containers/json", params={"all":"1"})).json()
    for container in containers:
        if (container.get("Labels") or {}).get("com.docker.compose.project") == detail["stack"]["name"]: continue
        if any(int(p.get("PublicPort") or 0) == backend_port for p in (container.get("Ports") or [])):
            raise HTTPException(409, "Backend port " + str(backend_port) + " už používá jiný kontejner.")
    try:
        await _redeploy_stack_with_proxy_port(detail, endpoint_id, service, container_port, backend_port)
        try:
            save_stack_proxy_route(detail["stack"]["name"], host, service, container_port, backend_port, True)
        except Exception as exc:
            if "UNIQUE" in str(exc).upper(): raise HTTPException(409, "Doména už je přiřazena jinému směrování.")
            raise
        refreshed = await build_detail(stack_id)
        result = await sync_stack_proxy(refreshed, endpoint_id)
        created_route = next((r for r in get_stack_proxy_routes(detail["stack"]["name"]) if r["host"] == host), None)
        dns = {"managed": False, "status": "not-configured"}
        if created_route:
            site = (get_endpoint_settings().get(endpoint_id, {}).get("site") or "").strip().upper()
            try:
                dns = await ensure_route_dns(detail["stack"]["name"], created_route["id"], host, site)
            except Exception as exc:
                dns = {"managed": False, "status": "error", "error": str(exc)}
        return {"ok": True, "host": host, "service": service, "container_port": container_port, "backend_port": backend_port, "proxy": result, "dns": dns}
    except HTTPException: raise
    except Exception as exc: raise HTTPException(502, "Přidání směrování selhalo: " + str(exc))


@app.delete("/api/stacks/{stack_id}/proxy/routes/{route_id}")
async def proxy_route_delete(stack_id: int, route_id: int, session=Depends(require_csrf)):
    if "migrations" not in user_permissions(session.get("user", "")) and "admin" not in user_permissions(session.get("user", "")):
        raise HTTPException(403, "Permission denied")
    detail = await build_detail(stack_id)
    routes = get_stack_proxy_routes(detail["stack"]["name"])
    route = next((r for r in routes if int(r["id"]) == int(route_id)), None)
    if not route: raise HTTPException(404, "Směrování nenalezeno.")
    # DNS first: if an owned record was changed outside DSM, refuse deletion
    # rather than deleting either the DNS record or the application route blindly.
    dns = await delete_route_dns(detail["stack"]["name"], route_id, route["host"]) if vas_hosting_enabled() else {"managed": False, "status": "disabled"}
    delete_stack_proxy_route(detail["stack"]["name"], route_id)
    refreshed = await build_detail(stack_id)
    if refreshed.get("domains"):
        result = await sync_stack_proxy(refreshed, int(detail["stack"]["endpoint_id"]))
    else:
        site = get_endpoint_settings().get(int(detail["stack"]["endpoint_id"]), {}).get("site")
        await remove_stack_proxy(detail["stack"]["name"], site)
        result = {"configured": False}
    return {"ok": True, "proxy": result, "dns": dns}


@app.put("/api/stacks/{stack_id}/proxy")
async def proxy_configure(stack_id: int, request: Request, session=Depends(require_csrf)):
    # Backward-compatible endpoint: now appends a route instead of replacing the stack domain.
    return await proxy_route_create(stack_id, request, session)

@app.post("/api/stacks/{stack_id}/proxy/sync")
async def proxy_sync(stack_id: int, session=Depends(require_csrf)):
    if "migrations" not in user_permissions(session.get("user", "")) and "admin" not in user_permissions(session.get("user", "")):
        raise HTTPException(403, "Permission denied")
    from .general import build_detail
    detail = await build_detail(stack_id)
    try:
        return await sync_stack_proxy(detail, int(detail["stack"]["endpoint_id"]))
    except Exception as exc:
        raise HTTPException(502, "Traefik sync selhal: " + str(exc))
