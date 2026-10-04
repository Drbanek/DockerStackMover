import subprocess
import os
import asyncio
import ipaddress
import os
import secrets
import shlex
import json
import queue
import time

import httpx
from fastapi import Depends, HTTPException, Request

from ..core import app, current_session, require_csrf, user_permissions, setting_set, save_site
from .provisioning import _ssh, _run


@app.post("/api/bootstrap/portainer")
async def bootstrap_portainer(request: Request, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user", "")):
        raise HTTPException(403, "Permission denied")
    p = await request.json()
    host = str(p.get("host") or "").strip()
    user = str(p.get("ssh_user") or "").strip()
    password = str(p.get("ssh_password") or "")
    site = str(p.get("site") or "MAIN").strip().upper()
    try:
        host_addr = ipaddress.ip_address(host)
        if host_addr.version != 4:
            raise ValueError("IPv4 required")
        parts = host.split(".")
        lan_ip = ".".join(parts[:3] + ["8"])
    except ValueError as exc:
        raise HTTPException(400, "Neplatná SSH IPv4 adresa: " + str(exc))
    wg_endpoint = lan_ip + ":51820"
    public_ip = ""
    ssh_port = int(p.get("ssh_port") or 22)
    if not host or not user or not password or not site:
        raise HTTPException(400, "Vyplň lokalitu, SSH adresu, uživatele a heslo.")
    try:
        ipaddress.ip_address(host)
        ipaddress.ip_address(lan_ip)
    except ValueError as exc:
        raise HTTPException(400, "Neplatná IPv4 adresa: " + str(exc))

    c = None
    try:
        c = await __import__("asyncio").to_thread(_ssh, host, ssh_port, user, password)
        cmd = r"""set -e
source /etc/os-release
test "$ID" = ubuntu
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl wireguard iputils-arping
if ! command -v docker >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" >/etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker
hostnamectl set-hostname __HOSTNAME__
install -d -m 700 /etc/wireguard
if [ ! -f /etc/wireguard/hub.key ]; then
  umask 077
  wg genkey | tee /etc/wireguard/hub.key | wg pubkey >/etc/wireguard/hub.pub
fi
PRIV=$(cat /etc/wireguard/hub.key)
cat >/etc/wireguard/wg-dsm.conf <<EOF
[Interface]
Address = 10.200.1.8/16
ListenPort = 51820
PrivateKey = $PRIV
EOF
chmod 600 /etc/wireguard/wg-dsm.conf
printf 'net.ipv4.ip_forward=1\n' >/etc/sysctl.d/99-dockerstackmover-wg-forward.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null
systemctl enable --now wg-quick@wg-dsm
docker volume create portainer_data >/dev/null
docker rm -f portainer >/dev/null 2>&1 || true
docker pull portainer/portainer-ce:2.45.1
docker run -d --name portainer --restart=always -p 9443:9443 -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce:2.45.1 >/dev/null
for i in $(seq 1 45); do
  curl -kfsS https://127.0.0.1:9443/api/system/status >/dev/null 2>&1 && exit 0
  sleep 2
done
exit 51
""".replace("__HOSTNAME__", shlex.quote(site + "-PORTAINER"))
        await __import__("asyncio").to_thread(_run, c, cmd, password, 1200)
        hub_pub = await __import__("asyncio").to_thread(_run, c, "cat /etc/wireguard/hub.pub", password)
    except Exception as exc:
        raise HTTPException(502, "Bootstrap Portaineru selhal: " + str(exc))
    finally:
        if c:
            c.close()

    url = "https://" + lan_ip + ":9443"
    admin_password = secrets.token_urlsafe(18)
    try:
        async with httpx.AsyncClient(base_url=url, verify=False, timeout=20) as pc:
            init = await pc.post("/api/users/admin/init", json={"Username": "admin", "Password": admin_password})
            if init.status_code not in (200, 201, 409):
                raise RuntimeError("admin init HTTP " + str(init.status_code) + ": " + init.text[:200])
            auth = await pc.post("/api/auth", json={"Username": "admin", "Password": admin_password})
            if auth.status_code != 200:
                if init.status_code == 409:
                    raise RuntimeError("Portainer už je inicializovaný. Pro bezpečné převzetí je potřeba jeho existující API token.")
                raise RuntimeError("auth HTTP " + str(auth.status_code))
            jwt = auth.json().get("jwt")
            if not jwt:
                raise RuntimeError("Portainer auth nevrátil JWT.")
            me = await pc.get("/api/users/me", headers={"Authorization": "Bearer " + jwt})
            if me.status_code != 200:
                raise RuntimeError("users/me HTTP " + str(me.status_code))
            uid = me.json().get("Id")
            tok = await pc.post("/api/users/" + str(uid) + "/tokens",
                                headers={"Authorization": "Bearer " + jwt},
                                json={"description": "DockerStackMover bootstrap", "password": admin_password})
            if tok.status_code not in (200, 201):
                raise RuntimeError("API token HTTP " + str(tok.status_code) + ": " + tok.text[:200])
            api_key = tok.json().get("rawAPIKey") or tok.json().get("apiKey")
            if not api_key:
                raise RuntimeError("Portainer nevrátil API key.")
            check = await pc.get("/api/endpoints", headers={"X-API-Key": api_key})
            if check.status_code != 200:
                raise RuntimeError("ověření API key selhalo HTTP " + str(check.status_code))
    except Exception as exc:
        raise HTTPException(502, "Portainer běží, ale automatická inicializace API selhala: " + str(exc))

    setting_set("portainer_url", url)
    setting_set("portainer_token", api_key, True)
    setting_set("main_site", site)
    setting_set("wg_hub_lan_ip", lan_ip)
    setting_set("wg_hub_endpoint", wg_endpoint)
    setting_set("wg_hub_public_key", hub_pub)
    setting_set("main_public_ip", public_ip)
    return {
        "ok": True,
        "site": site,
        "portainer_url": url,
        "hub_management_ip": "10.200.1.8",
        "hub_public_key": hub_pub,
        "wg_endpoint": wg_endpoint,
        "portainer_admin_user": "admin",
        "portainer_admin_password": admin_password,
        "password_is_one_time": True,
    }


@app.get("/api/bootstrap/discovery")
async def bootstrap_discovery(session=Depends(current_session)):
    """Find SSH-capable hosts in the MGMT LAN without trying credentials."""
    if "admin" not in user_permissions(session.get("user", "")):
        raise HTTPException(403, "Permission denied")
    host_ip = os.environ.get("DSM_HOST_IP", "").strip()
    prefix = os.environ.get("DSM_HOST_PREFIX", "").strip()
    try:
        network = ipaddress.ip_network(f"{host_ip}/{prefix}", strict=False)
    except ValueError:
        raise HTTPException(500, "MGMT subnet není dostupný. Spusť DSM pomocí aktuálního install.sh.")
    if network.version != 4 or network.num_addresses > 4096:
        raise HTTPException(400, "Discovery podporuje IPv4 subnety do 4096 adres.")

    sem = asyncio.Semaphore(128)

    async def probe(ip):
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(str(ip), 22), timeout=0.45
                )
                banner = ""
                try:
                    banner = (await asyncio.wait_for(reader.readline(), timeout=0.25)).decode(
                        "utf-8", "replace"
                    ).strip()[:120]
                except Exception:
                    pass
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return {"ip": str(ip), "ssh": True, "banner": banner}
            except Exception:
                return None

    found = await asyncio.gather(*(probe(ip) for ip in network.hosts()))
    hosts = [x for x in found if x]
    hosts.sort(key=lambda x: ipaddress.ip_address(x["ip"]))
    return {"subnet": str(network), "hosts": hosts, "count": len(hosts)}


@app.post("/api/bootstrap/portainer/stream")
async def bootstrap_portainer_stream(request: Request, session=Depends(require_csrf)):
    """Fresh first-site bootstrap with live NDJSON progress."""
    if "admin" not in user_permissions(session.get("user", "")):
        raise HTTPException(403, "Permission denied")
    p = await request.json()
    host = str(p.get("host") or "").strip()
    user = str(p.get("ssh_user") or "").strip()
    password = str(p.get("ssh_password") or "")
    site = str(p.get("site") or "").strip().upper()
    ssh_port = int(p.get("ssh_port") or 22)
    if not host or not user or not password or not site:
        raise HTTPException(400, "Vyplň lokalitu, SSH adresu, uživatele a heslo.")
    try:
        addr = ipaddress.ip_address(host)
        if addr.version != 4:
            raise ValueError("IPv4 required")
    except ValueError as exc:
        raise HTTPException(400, "Neplatná SSH IPv4 adresa: " + str(exc))
    lan_ip = ".".join(host.split(".")[:3] + ["8"])
    wg_endpoint = lan_ip + ":51820"

    q = queue.Queue()

    def emit(step, status="done", detail=""):
        q.put({"type": "progress", "step": step, "status": status, "detail": detail})

    def worker():
        conn = None
        try:
            emit("ssh", "running", "Připojuji se k " + host)
            conn = _ssh(host, ssh_port, user, password)
            emit("ssh", "done", "SSH připojení ověřeno")

            emit("ubuntu", "running", "Kontroluji operační systém")
            os_id = _run(conn, "source /etc/os-release; printf '%s' \"$ID\"", password)
            if os_id.strip() != "ubuntu":
                raise RuntimeError("Podporován je pouze Ubuntu Server.")
            emit("ubuntu", "done", "Ubuntu ověřeno")

            emit("network", "running", "Zjišťuji interface, gateway, prefix a DNS")
            net = _run(conn, r"""set -e
IFACE=$(ip -4 route show default | awk 'NR==1{print $5}')
CIDR=$(ip -o -4 addr show dev "$IFACE" scope global | awk 'NR==1{print $4}')
GW=$(ip -4 route show default | awk 'NR==1{print $3}')
DNS=$(resolvectl dns "$IFACE" 2>/dev/null | awk -F': ' 'NR==1{print $2}' | xargs | tr ' ' ',')
printf '%s|%s|%s|%s' "$IFACE" "$CIDR" "$GW" "$DNS"
""", password)
            iface, cidr, gateway, dns = (net.split("|", 3) + ["", "", "", ""])[:4]
            prefix = cidr.split("/", 1)[1] if "/" in cidr else "24"
            if not iface or not gateway:
                raise RuntimeError("Nepodařilo se zjistit síťovou konfiguraci.")
            emit("network", "done", f"Cíl {lan_ip}/{prefix}, gateway {gateway}")

            emit("hostname", "running", "Nastavuji hostname")
            _run(conn, "hostnamectl set-hostname " + shlex.quote(site + "-PORTAINER"), password)
            emit("hostname", "done", site + "-PORTAINER")

            emit("docker", "running", "Instaluji Docker")
            _run(conn, r"""set -e
source /etc/os-release
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl wireguard iputils-arping
if ! command -v docker >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" >/etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker
""", password, 1200)
            emit("docker", "done", "Docker připraven")

            emit("wireguard", "running", "Vytvářím centrální WireGuard HUB")
            _run(conn, r"""set -e
install -d -m 700 /etc/wireguard
if [ ! -f /etc/wireguard/hub.key ]; then
  umask 077
  wg genkey | tee /etc/wireguard/hub.key | wg pubkey >/etc/wireguard/hub.pub
fi
PRIV=$(cat /etc/wireguard/hub.key)
cat >/etc/wireguard/wg-dsm.conf <<EOF
[Interface]
Address = 10.200.1.8/16
ListenPort = 51820
PrivateKey = $PRIV
EOF
chmod 600 /etc/wireguard/wg-dsm.conf
printf 'net.ipv4.ip_forward=1\n' >/etc/sysctl.d/99-dockerstackmover-wg-forward.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null
systemctl enable --now wg-quick@wg-dsm
""", password)
            hub_pub = _run(conn, "cat /etc/wireguard/hub.pub", password).strip()

            # MGMT WireGuard is prepared by install.sh on the host. The app container
            # only carries its public key to the HUB; it must never require host sudo.
            mgmt_pub = os.environ.get("DSM_WG_PUBLIC_KEY", "").strip()
            if not mgmt_pub:
                raise RuntimeError("MGMT WireGuard není připraven. Aktualizuj MGMT pomocí aktuálního install.sh.")
            peer_cmd = "wg set wg-dsm peer " + shlex.quote(mgmt_pub) + " allowed-ips 10.200.1.10/32; " + \
                       "wg-quick save wg-dsm >/dev/null"
            _run(conn, peer_cmd, password)

            # Ask the narrow host-side broker to activate MGMT WireGuard.
            # A bind-mounted executable would still run inside the container
            # namespace, so it cannot configure the host. The systemd path
            # service installed by install.sh performs the privileged action.
            request_dir = "/host-requests"
            if not os.path.isdir(request_dir):
                raise RuntimeError("MGMT WireGuard request bridge chybí. Aktualizuj MGMT pomocí aktuálního install.sh.")
            request_path = os.path.join(request_dir, "request")
            result_path = os.path.join(request_dir, "result")
            try:
                os.unlink(result_path)
            except FileNotFoundError:
                pass
            tmp_path = request_path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as fh:
                fh.write(hub_pub + "\n" + wg_endpoint + "\n")
            os.replace(tmp_path, request_path)
            broker_result = ""
            for _ in range(60):
                time.sleep(0.25)
                try:
                    with open(result_path, "r", encoding="utf-8") as fh:
                        broker_result = fh.read().strip()
                except FileNotFoundError:
                    continue
                break
            if broker_result != "OK":
                raise RuntimeError("MGMT WireGuard aktivace selhala: " + (broker_result or "host služba neodpověděla"))
            emit("wireguard", "done", "WG HUB 10.200.1.8 + MGMT 10.200.1.10 připraveny")

            emit("portainer", "running", "Instaluji Portainer Server")
            _run(conn, r"""set -e
docker volume create portainer_data >/dev/null
docker rm -f portainer >/dev/null 2>&1 || true
docker pull portainer/portainer-ce:2.45.1
docker run -d --name portainer --restart=always -p 9443:9443 -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce:2.45.1 >/dev/null
for i in $(seq 1 45); do
  curl -kfsS https://127.0.0.1:9443/api/system/status >/dev/null 2>&1 && exit 0
  sleep 2
done
exit 51
""", password, 1200)
            setup_token = _run(conn, r"""set -e
for i in $(seq 1 20); do
  TOKEN=$(docker logs portainer 2>&1 | awk -F'setup_token=' 'NF>1 {print $2}' | awk '{print $1}' | tail -n1)
  case "$TOKEN" in
    (*[!0-9a-fA-F]*|'') TOKEN="" ;;
  esac
  [ "${#TOKEN}" -eq 64 ] || TOKEN=""
  if [ -n "$TOKEN" ]; then
    printf '%s' "$TOKEN"
    exit 0
  fi
  sleep 1
done
exit 52
""", password).strip()
            if not setup_token:
                raise RuntimeError("Portainer setup token nebyl nalezen.")
            emit("portainer", "done", "Portainer běží, setup token načten")

            if host != lan_ip:
                emit("lan", "running", "Ověřuji a přepínám PORTAINER na " + lan_ip)
                network = ipaddress.ip_network(cidr, strict=False)
                target = ipaddress.ip_address(lan_ip)
                if target not in network or target in (network.network_address, network.broadcast_address):
                    raise RuntimeError(f"Cílová LAN IP {lan_ip} není použitelná v síti {network}.")
                dns_addrs = []
                for value in dns.split(","):
                    value = value.strip().split("%", 1)[0]
                    try:
                        ipaddress.ip_address(value)
                        dns_addrs.append(value)
                    except ValueError:
                        pass
                if not dns_addrs:
                    dns_addrs = [gateway]
                dns_yaml = ", ".join(dns_addrs)
                # Duplicate Address Detection on the actual L2 segment.
                # Ubuntu Server may not have arping installed. Treat a missing/broken
                # probe as an error, never as proof that the address is occupied.
                duplicate = _run(conn, "if ! command -v arping >/dev/null 2>&1; then echo NO_ARPING; " +
                                 "elif arping -D -I " + shlex.quote(iface) + " -c 2 -w 3 " +
                                 shlex.quote(lan_ip) + " >/dev/null 2>&1; then echo FREE; " +
                                 "else rc=$?; [ \"$rc\" -eq 1 ] && echo USED || echo PROBE_ERROR:$rc; fi",
                                 password)
                duplicate = duplicate.strip()
                if duplicate == "NO_ARPING":
                    raise RuntimeError("Nelze ověřit cílovou LAN IP: na PORTAINER serveru chybí arping.")
                if duplicate.startswith("PROBE_ERROR:"):
                    raise RuntimeError("Kontrola cílové LAN IP selhala (" + duplicate + ").")
                if duplicate != "FREE":
                    raise RuntimeError("Cílová LAN IP " + lan_ip + " už je na síti obsazená.")
                switch = r"""set -e
NETPLAN=$(find /etc/netplan -maxdepth 1 -type f \( -name '*.yaml' -o -name '*.yml' \) | head -n1)
test -n "$NETPLAN"
cp -a "$NETPLAN" "$NETPLAN.dsm-backup"
cat >"$NETPLAN" <<EOF
network:
  version: 2
  ethernets:
    __IFACE__:
      dhcp4: false
      dhcp6: false
      addresses:
        - __LAN__/__PREFIX__
      routes:
        - to: default
          via: __GW__
      nameservers:
        addresses: [__DNS__]
EOF
chmod 600 "$NETPLAN"
netplan generate
nohup bash -c 'sleep 2; netplan apply' >/var/log/dockerstackmover-portainer-ip-switch.log 2>&1 &
""".replace("__IFACE__", iface).replace("__LAN__", lan_ip).replace("__PREFIX__", prefix).replace("__GW__", gateway).replace("__DNS__", dns_yaml)
                _run(conn, switch, password)
                # Do not report success merely because the asynchronous switch was scheduled.
                # The API stage verifies the new address; keep this step running until then.
            else:
                emit("lan", "done", "LAN IP už je " + lan_ip)
        except Exception as exc:
            q.put({"type": "error", "step": "bootstrap", "detail": str(exc)})
            return
        finally:
            if conn:
                conn.close()

        async def finish_portainer():
            emit("api", "running", "Inicializuji Portainer API")
            url = "https://" + lan_ip + ":9443"
            # Wait for the new LAN address after Netplan switch.
            last = None
            for _ in range(40):
                try:
                    async with httpx.AsyncClient(base_url=url, verify=False, timeout=4) as pc:
                        s = await pc.get("/api/system/status")
                        if s.status_code == 200:
                            emit("lan", "done", "LAN IP ověřena: " + lan_ip)
                            break
                except Exception as exc:
                    last = exc
                await asyncio.sleep(1)
            else:
                raise RuntimeError("Portainer není po změně IP dostupný na " + url + ": " + str(last or ""))

            admin_password = secrets.token_urlsafe(18)
            async with httpx.AsyncClient(base_url=url, verify=False, timeout=20) as pc:
                init = await pc.post("/api/users/admin/init", headers={"X-Setup-Token": setup_token}, json={"Username": "admin", "Password": admin_password})
                if init.status_code not in (200, 201):
                    raise RuntimeError("Portainer admin init HTTP " + str(init.status_code))
                auth = await pc.post("/api/auth", json={"Username": "admin", "Password": admin_password})
                if auth.status_code != 200:
                    raise RuntimeError("Portainer auth HTTP " + str(auth.status_code))
                jwt = auth.json().get("jwt")
                me = await pc.get("/api/users/me", headers={"Authorization": "Bearer " + jwt})
                uid = me.json().get("Id")
                tok = await pc.post("/api/users/" + str(uid) + "/tokens",
                    headers={"Authorization": "Bearer " + jwt},
                    json={"description": "DockerStackMover bootstrap", "password": admin_password})
                if tok.status_code not in (200, 201):
                    raise RuntimeError("API token HTTP " + str(tok.status_code))
                api_key = tok.json().get("rawAPIKey") or tok.json().get("apiKey")
                if not api_key:
                    raise RuntimeError("Portainer nevrátil API key.")
                check = await pc.get("/api/endpoints", headers={"X-API-Key": api_key})
                if check.status_code != 200:
                    raise RuntimeError("Ověření API key HTTP " + str(check.status_code))
            emit("api", "done", "Portainer API token vytvořen")

            emit("save", "running", "Ukládám první infrastrukturu")
            setting_set("portainer_url", url)
            setting_set("portainer_token", api_key, True)
            setting_set("main_site", site)
            setting_set("wg_hub_lan_ip", lan_ip)
            setting_set("wg_hub_endpoint", wg_endpoint)
            setting_set("wg_hub_public_key", hub_pub)
            setting_set("main_public_ip", "")
            setting_set("provisioning_hub_host", lan_ip)
            setting_set("provisioning_hub_ssh_user", user)
            setting_set("provisioning_hub_endpoint", wg_endpoint)
            save_site(site, ".".join(lan_ip.split(".")[:3])+".0/24", 1, "", user)
            emit("save", "done", "Infrastruktura uložena")
            return {
                "ok": True, "site": site, "portainer_url": url,
                "lan_ip": lan_ip, "hub_management_ip": "10.200.1.8",
                "hub_public_key": hub_pub, "wg_endpoint": wg_endpoint,
                "portainer_admin_user": "admin",
                "portainer_admin_password": admin_password,
                "password_is_one_time": True,
            }

        try:
            result = asyncio.run(finish_portainer())
            q.put({"type": "result", "result": result})
        except Exception as exc:
            q.put({"type": "error", "step": "api", "detail": str(exc)})

    async def events():
        task = asyncio.create_task(asyncio.to_thread(worker))
        while True:
            item = await asyncio.to_thread(q.get)
            yield json.dumps(item, ensure_ascii=False) + "\n"
            if item.get("type") in ("result", "error"):
                break
        await task

    from fastapi.responses import StreamingResponse
    return StreamingResponse(events(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
