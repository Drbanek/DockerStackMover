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


def _backend_port_for_stack(stack_name):
    # Stable, deterministic high port. Collisions are checked before deployment.
    digest = int(hashlib.sha256(str(stack_name).encode("utf-8")).hexdigest()[:8], 16)
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


@app.put("/api/stacks/{stack_id}/proxy")
async def proxy_configure(stack_id: int, request: Request, session=Depends(require_csrf)):
    if "migrations" not in user_permissions(session.get("user", "")) and "admin" not in user_permissions(session.get("user", "")):
        raise HTTPException(403, "Permission denied")
    payload = await request.json()
    host = str(payload.get("host") or "").strip().lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9.-]+", host) or "." not in host:
        raise HTTPException(400, "Zadej platnou doménu, např. test01.lukas.cloud")
    detail = await build_detail(stack_id)
    endpoint_id = int(detail["stack"]["endpoint_id"])
    service, container_port = await _choose_proxy_service(detail)
    backend_port = _backend_port_for_stack(detail["stack"]["name"])
    # Refuse a deterministic port collision with another container.
    containers = (await docker_get(endpoint_id, "/containers/json", params={"all":"1"})).json()
    for container in containers:
        if (container.get("Labels") or {}).get("com.docker.compose.project") == detail["stack"]["name"]:
            continue
        for p in container.get("Ports") or []:
            if int(p.get("PublicPort") or 0) == backend_port:
                raise HTTPException(409, "Automatický backend port " + str(backend_port) + " už používá jiný kontejner.")
    try:
        await _redeploy_stack_with_proxy_port(detail, endpoint_id, service, container_port, backend_port)
        save_stack_proxy_setting(detail["stack"]["name"], host, service, container_port, backend_port, True)
        refreshed = await build_detail(stack_id)
        result = await sync_stack_proxy(refreshed, endpoint_id)
        return {"ok": True, "host": host, "https": True, "service": service, "container_port": container_port,
                "backend_port": backend_port, "proxy": result}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, "Nastavení domény selhalo: " + str(exc))

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
