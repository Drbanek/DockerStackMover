import asyncio
import ipaddress
import shlex
import socket
import time
import json
import queue
import uuid

import paramiko
from fastapi import Depends, HTTPException, Request

from ..core import app, require_csrf, require_permission, user_permissions, client, save_endpoint_setting, get_endpoint_settings, get_sites, get_site, save_site, next_management_octet, setting_get, setting_set


def _ssh(host, port, username, password):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(hostname=host, port=int(port or 22), username=username, password=password,
              timeout=10, banner_timeout=10, auth_timeout=10)
    return c


def _run(c, command, password=None, timeout=300):
    if password is not None:
        command = "sudo -S -p '' bash -lc " + shlex.quote(command)
    # sudo -S does not need a PTY on Ubuntu. A PTY echoes the password into the
    # terminal stream and can leak/control-character-corrupt multiline commands.
    stdin, stdout, stderr = c.exec_command(command, timeout=timeout, get_pty=False)
    if password is not None:
        stdin.write(password + "\n"); stdin.flush()
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    rc = stdout.channel.recv_exit_status()
    if rc:
        message = (err or out or ("command failed: " + str(rc))).strip()
        if password:
            message = message.replace(password, "[REDACTED]")
        raise RuntimeError(message)
    return out.strip()


def _provision(payload, progress=None):
    progress = progress or (lambda step, status='done', detail='': None)
    host = str(payload.get("host") or "").strip()
    user = str(payload.get("ssh_user") or "").strip()
    password = str(payload.get("ssh_password") or "")
    hub_host = str(payload.get("hub_host") or "").strip()
    hub_user = str(payload.get("hub_ssh_user") or "").strip()
    hub_password = str(payload.get("hub_ssh_password") or "")
    site = str(payload.get("site") or "").strip().upper()
    role = str(payload.get("role") or "NODE").strip().upper()
    lan_ip = str(payload.get("lan_ip") or "").strip()
    mgmt_ip = str(payload.get("management_ip") or "").strip()
    hub_mgmt_ip = str(payload.get("hub_management_ip") or "10.200.1.8").strip()
    manager_mgmt_ip = str(payload.get("manager_management_ip") or "10.200.1.10").strip()
    data_disk = str(payload.get("data_disk") or "AUTO").strip()
    hub_endpoint = str(payload.get("hub_endpoint") or "").strip()
    name = str(payload.get("name") or (site + "-" + role)).strip().upper()
    ssh_port = int(payload.get("ssh_port") or 22)
    hub_ssh_port = int(payload.get("hub_ssh_port") or 22)
    if not all((host,user,password,hub_host,hub_user,hub_password,site,lan_ip,mgmt_ip,hub_endpoint)):
        raise ValueError("Chybí povinné provisioning údaje.")
    ipaddress.ip_address(host); ipaddress.ip_address(lan_ip); ipaddress.ip_address(mgmt_ip); ipaddress.ip_address(hub_mgmt_ip); ipaddress.ip_address(manager_mgmt_ip)
    if not mgmt_ip.startswith("10.200."):
        raise ValueError("Management IP musí být z overlay 10.200.0.0/16.")
    steps=[]
    progress("ssh","running","Připojuji se přes SSH…")
    target=_ssh(host,ssh_port,user,password)
    hub=None
    try:
        steps.append("SSH target OK"); progress("ssh","done","SSH target OK")
        progress("preflight","running","Kontroluji Ubuntu, route a sudo…")
        pre=_run(target,"source /etc/os-release; test \"$ID\" = ubuntu; ip -4 route show default | head -1; command -v sudo >/dev/null")
        existing_docker=_run(target,"if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then echo yes; else echo no; fi",password)=="yes"
        existing_agent=_run(target,"if command -v docker >/dev/null 2>&1 && docker ps -a --format '{{.Names}}' | grep -qx portainer_agent; then echo yes; else echo no; fi",password)=="yes"
        repair_mode=existing_docker or existing_agent
        mode_detail="REPAIR existujícího serveru" if repair_mode else "nový server"
        steps.append("Pre-flight OK: "+pre.splitlines()[-1]+" · "+mode_detail); progress("preflight","done","Pre-flight OK · "+mode_detail)
        if host != lan_ip:
            progress("lan","running","Nastavuji LAN IP "+lan_ip+"…")
            netcmd=f"""IF=$(ip -4 route show default | awk 'NR==1{{print $5}}'); GW=$(ip -4 route show default | awk 'NR==1{{print $3}}'); CIDR=$(ip -o -4 addr show dev "$IF" scope global | awk 'NR==1{{print $4}}'); PREFIX="${{CIDR#*/}}"; test "$PREFIX" = 24; cat >/etc/netplan/99-dockerstackmover.yaml <<EOF
network:
  version: 2
  ethernets:
    $IF:
      dhcp4: false
      addresses: [{lan_ip}/24]
      routes:
        - to: default
          via: $GW
      nameservers:
        addresses: [1.1.1.1,8.8.8.8]
EOF
netplan generate
nohup sh -c 'sleep 2; netplan apply' >/tmp/dsm-netplan.log 2>&1 &"""
            _run(target,netcmd,password)
            target.close(); target=None
            last=None
            for _ in range(20):
                time.sleep(2)
                try:
                    target=_ssh(lan_ip,ssh_port,user,password); break
                except Exception as exc: last=exc
            if target is None:
                raise RuntimeError("LAN IP byla změněna, ale SSH na nové adrese "+lan_ip+" není dostupné: "+str(last))
            host=lan_ip
            steps.append("LAN IP changed to "+lan_ip); progress("lan","done","LAN IP changed to "+lan_ip)
        if host == lan_ip: progress("lan","done","LAN IP už je nastavena: "+lan_ip)
        progress("hostname","running","Nastavuji hostname "+name+"…")
        _run(target,"hostnamectl set-hostname "+shlex.quote(name),password)
        steps.append("Hostname "+name); progress("hostname","done","Hostname "+name)
        progress("wg_key","running","Čekám na dokončení automatických aktualizací systému…")
        apt_wait = """deadline=$((SECONDS+300))
while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "Timeout: APT/dpkg je stále používán jiným procesem po 300 s." >&2
    exit 75
  fi
  sleep 3
done
while dpkg --audit 2>/dev/null | grep -q .; do
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "Timeout: dpkg není po 300 s v konzistentním stavu." >&2
    exit 76
  fi
  sleep 3
done"""
        _run(target,apt_wait,password,330)
        progress("wg_key","running","Instaluji balíčky a připravuji WireGuard klíče…")
        _run(target,"apt-get -o DPkg::Lock::Timeout=300 update && DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y wireguard ca-certificates curl nftables",password,900)
        _run(target,"install -d -m 700 /etc/wireguard; if [ ! -f /etc/wireguard/dsm.key ]; then umask 077; wg genkey | tee /etc/wireguard/dsm.key | wg pubkey > /etc/wireguard/dsm.pub; fi",password)
        peer_pub=_run(target,"cat /etc/wireguard/dsm.pub",password)
        steps.append("WireGuard keypair OK"); progress("wg_key","done","WireGuard keypair OK")
        progress("wg_peer","running","Registruji peer na MAIN…")
        hub=_ssh(hub_host,hub_ssh_port,hub_user,hub_password)
        hub_pub=_run(hub,"cat /etc/wireguard/hub.pub",hub_password)
        hub_conf="/etc/wireguard/wg-dsm.conf"
        add=f"""grep -qF {shlex.quote(peer_pub)} {hub_conf} || cat >>{hub_conf} <<'EOF'

# {name}
[Peer]
PublicKey = {peer_pub}
AllowedIPs = {mgmt_ip}/32
EOF
wg set wg-dsm peer {peer_pub} allowed-ips {mgmt_ip}/32"""
        _run(hub,add,hub_password)
        steps.append("Peer registered on MAIN"); progress("wg_peer","done","Peer registered on MAIN")
        progress("wg_start","running","Zapínám WireGuard overlay…")
        cfg=f"""cat >/etc/wireguard/wg-dsm.conf <<'EOF'
[Interface]
Address = {mgmt_ip}/32
PrivateKey = $(cat /etc/wireguard/dsm.key)
EOF
sed -i "s|PrivateKey = .*|PrivateKey = $(cat /etc/wireguard/dsm.key)|" /etc/wireguard/wg-dsm.conf
cat >>/etc/wireguard/wg-dsm.conf <<'EOF'

[Peer]
PublicKey = {hub_pub}
Endpoint = {hub_endpoint}
AllowedIPs = 10.200.0.0/16
PersistentKeepalive = 25
EOF
chmod 600 /etc/wireguard/wg-dsm.conf
systemctl enable --now wg-quick@wg-dsm"""
        _run(target,cfg,password)
        steps.append("WireGuard started"); progress("wg_start","done","WireGuard started")
        progress("wg_handshake","running","Čekám na WireGuard handshake…")
        time.sleep(2)
        hs=_run(hub,f"wg show wg-dsm latest-handshakes | grep -F {shlex.quote(peer_pub)} || true",hub_password)
        if not hs or hs.split()[-1]=="0":
            raise RuntimeError("WireGuard handshake se nepotvrdil.")
        steps.append("WireGuard handshake OK"); progress("wg_handshake","done","WireGuard handshake OK")
        # The hub routes management traffic between WireGuard peers. Keep this
        # independent of Docker's FORWARD policy (which is commonly DROP).
        progress("wg_forward","running","Ověřuji forwarding management overlay…")
        _run(hub,"sysctl -w net.ipv4.ip_forward=1 >/dev/null; printf 'net.ipv4.ip_forward=1\\n' >/etc/sysctl.d/99-dockerstackmover-wg-forward.conf; iptables -C FORWARD -i wg-dsm -o wg-dsm -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i wg-dsm -o wg-dsm -j ACCEPT",hub_password)
        steps.append("WireGuard peer forwarding OK"); progress("wg_forward","done","WireGuard peer forwarding OK")
        if role == "NODE":
            progress("data_disk","running","Kontroluji/připravuji DATA disk /srv…")
            diskcmd = """if findmnt -rn -T /srv >/dev/null 2>&1 && [ "$(findmnt -rn -T /srv -o TARGET)" = "/srv" ]; then
  echo "EXISTING $(findmnt -rn -T /srv -o SOURCE)"
  exit 0
fi
ROOT_SRC=$(findmnt -no SOURCE /)
ROOT_DISK=$(lsblk -s -npo NAME,TYPE "$ROOT_SRC" 2>/dev/null | awk '$2=="disk"{print $1; exit}')
[ -n "$ROOT_DISK" ] || exit 40
REQUESTED=__DATA_DISK__
REPAIR_MODE=__REPAIR_MODE__
if [ "$REPAIR_MODE" = yes ] && [ "$REQUESTED" = AUTO ]; then
  echo "REPAIR: /srv není samostatně připojené. Automatické formátování DATA disku je z bezpečnostních důvodů zakázáno; nejdřív ověř data a zadej disk explicitně." >&2
  exit 46
fi
if [ "$REQUESTED" = AUTO ]; then
  CANDIDATES=""
  while read -r DEV TYPE; do
    [ "$TYPE" = disk ] || continue
    [ "$DEV" = "$ROOT_DISK" ] && continue
    [ -n "$(lsblk -nrpo MOUNTPOINTS "$DEV" | tr -d '[:space:]')" ] && continue
    [ -n "$(lsblk -nrpo FSTYPE "$DEV" | tr -d '[:space:]')" ] && continue
    CANDIDATES="$CANDIDATES $DEV"
  done < <(lsblk -dpno NAME,TYPE)
  set -- $CANDIDATES
  [ "$#" -eq 1 ] || { echo "AUTO DATA disk vyžaduje právě jeden nepoužitý disk; nalezeno: $# ($CANDIDATES)" >&2; exit 41; }
  DISK="$1"
else
  DISK="$REQUESTED"
fi
[ -b "$DISK" ] || { echo "DATA disk $DISK neexistuje" >&2; exit 42; }
[ "$DISK" != "$ROOT_DISK" ] || { echo "Odmítám použít systémový disk $DISK" >&2; exit 43; }
[ -z "$(lsblk -nrpo MOUNTPOINTS "$DISK" | tr -d '[:space:]')" ] || { echo "DATA disk $DISK obsahuje připojený oddíl" >&2; exit 44; }
[ -z "$(lsblk -nrpo FSTYPE "$DISK" | tr -d '[:space:]')" ] || { echo "DATA disk $DISK obsahuje filesystem; odmítám automatické smazání" >&2; exit 45; }
apt-get -o DPkg::Lock::Timeout=300 update
DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y xfsprogs parted
wipefs -a "$DISK"
parted -s "$DISK" mklabel gpt mkpart primary xfs 0% 100%
partprobe "$DISK"; sleep 2
PART="$DISK""1"; case "$DISK" in *nvme*|*mmcblk*) PART="$DISK""p1";; esac
mkfs.xfs -f "$PART"
mkdir -p /srv
UUID=$(blkid -s UUID -o value "$PART")
grep -qE '^[^#]+[[:space:]]+/srv[[:space:]]' /etc/fstab || echo "UUID=$UUID /srv xfs defaults,prjquota 0 2" >>/etc/fstab
mount /srv
mkdir -p /srv/stacks
chown -R root:docker /srv/stacks
chmod 2775 /srv/stacks
echo "CREATED $DISK -> $PART -> /srv"
"""
            diskcmd = diskcmd.replace("__DATA_DISK__", shlex.quote(data_disk or "AUTO"))
            diskcmd = diskcmd.replace("__REPAIR_MODE__", "yes" if repair_mode else "no")
            disk_result = _run(target,diskcmd,password,900)
            disk_detail=disk_result.splitlines()[-1]
            steps.append("DATA disk OK: "+disk_detail); progress("data_disk","done","DATA disk OK: "+disk_detail)
        progress("docker","running","Instaluji/opravuji Docker a Portainer Agent…")
        docker="""if ! command -v docker >/dev/null; then install -m 0755 -d /etc/apt/keyrings; curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc; chmod a+r /etc/apt/keyrings/docker.asc; . /etc/os-release; echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" >/etc/apt/sources.list.d/docker.list; apt-get -o DPkg::Lock::Timeout=300 update; DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; fi
systemctl enable --now docker
# NODE persistent named volumes live on the DATA filesystem while Docker
# images/layers remain on the SYSTEM filesystem. On a fresh NODE it is safe
# to stop Docker briefly and bind-mount only its volumes directory to /srv.
__NODE_VOLUME_SETUP__
docker info >/dev/null
docker rm -f portainer_agent >/dev/null 2>&1 || true
docker pull portainer/agent:2.45.1
docker run -d --name portainer_agent --restart=always -p 9001:9001 -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/docker/volumes:/var/lib/docker/volumes -v /:/host portainer/agent:2.45.1 >/dev/null
docker inspect portainer_agent >/dev/null 2>&1
docker port portainer_agent 9001/tcp | grep -q 9001"""
        if role == "NODE":
            if repair_mode:
                volume_setup = """if findmnt -rn -T /var/lib/docker/volumes -o TARGET,SOURCE | grep -q '^/var/lib/docker/volumes /srv/docker-volumes
        if role == "PROXY":
            progress("proxy","running","Instaluji/opravuji Traefik reverse proxy…")
            proxycmd = """install -d -m 755 /opt/traefik/dynamic /opt/traefik/letsencrypt /opt/traefik/config
touch /opt/traefik/letsencrypt/acme.json
chmod 600 /opt/traefik/letsencrypt/acme.json
cat >/opt/traefik/config/traefik.yml <<'DSMTRAEFIK'
api:
  dashboard: false
entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"
providers:
  file:
    directory: /etc/traefik/dynamic
    watch: true
certificatesResolvers:
  letsencrypt:
    acme:
      storage: /letsencrypt/acme.json
      httpChallenge:
        entryPoint: web
log:
  level: INFO
DSMTRAEFIK
cat >/opt/traefik/compose.yaml <<'DSMCOMPOSE'
services:
  traefik:
    image: traefik:v3.7
    container_name: traefik
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /opt/traefik/config/traefik.yml:/etc/traefik/traefik.yml:ro
      - /opt/traefik/dynamic:/etc/traefik/dynamic:ro
      - /opt/traefik/letsencrypt:/letsencrypt
DSMCOMPOSE
cd /opt/traefik
docker compose pull
docker compose up -d
for i in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Running}}' traefik 2>/dev/null || true)" = true ] && break
  sleep 1
done
[ "$(docker inspect -f '{{.State.Running}}' traefik 2>/dev/null || true)" = true ]
docker exec traefik traefik healthcheck >/dev/null 2>&1 || docker exec traefik traefik version >/dev/null
test -d /opt/traefik/dynamic
ss -lnt | grep -Eq '[:.]80[[:space:]]'
ss -lnt | grep -Eq '[:.]443[[:space:]]'"""
            _run(target,proxycmd,password,900)
            steps.append("Traefik PROXY OK"); progress("proxy","done","Traefik běží · dynamic config OK · porty 80/443 naslouchají")
        else:
            progress("proxy","done","Role NODE · Traefik se neinstaluje")
        progress("firewall","running","Aplikuji management firewall…")
        fw=f"""# Keep DSM firewall isolated from the host-wide nftables service.
# Loading /etc/nftables.conf can contain 'flush ruleset', which destroys Docker's
# DOCKER-* chains while dockerd is still running. Persist only our own table.
mkdir -p /etc/dockerstackmover
cat >/etc/dockerstackmover/firewall.nft <<'DSMFW'
table inet dockerstackmover-bootstrap {{
 chain input {{
  type filter hook input priority -10; policy accept;
  ct state established,related accept
  iifname lo accept
  iifname "wg-dsm" ip saddr {hub_mgmt_ip} tcp dport 9001 accept
  iifname "wg-dsm" ip saddr {manager_mgmt_ip} tcp dport 9100 accept
  tcp dport {{ 9001, 9100 }} drop
 }}
}}
DSMFW
nft -c -f /etc/dockerstackmover/firewall.nft
nft delete table inet dockerstackmover-bootstrap >/dev/null 2>&1 || true
nft -f /etc/dockerstackmover/firewall.nft
cat >/etc/systemd/system/dockerstackmover-firewall.service <<'DSMSVC'
[Unit]
Description=DockerStackMover management firewall
After=network-online.target docker.service
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c '/usr/sbin/nft delete table inet dockerstackmover-bootstrap >/dev/null 2>&1 || true; /usr/sbin/nft -f /etc/dockerstackmover/firewall.nft'
[Install]
WantedBy=multi-user.target
DSMSVC
systemctl daemon-reload
systemctl enable dockerstackmover-firewall.service
# Remove only the legacy DSM include/file; never reload the host-wide ruleset.
rm -f /etc/nftables.d/dockerstackmover-bootstrap.nft
sed -i '\\|include "/etc/nftables.d/\\*.nft"|d' /etc/nftables.conf 2>/dev/null || true
iptables -t filter -S DOCKER-FORWARD >/dev/null
docker port portainer_agent 9001/tcp | grep -q 9001"""
        _run(target,fw,password)
        steps.append("Management firewall OK"); progress("firewall","done","Management firewall OK")
        # Test the exact central management path before returning success.
        progress("main_test","running","Testuji MAIN → management IP :9001…")
        _run(hub,f"timeout 4 bash -lc '</dev/tcp/{mgmt_ip}/9001'")
        steps.append("MAIN -> "+mgmt_ip+":9001 OK"); progress("main_test","done","MAIN -> "+mgmt_ip+":9001 OK")
        return {"ok":True,"name":name,"site":site,"role":role,"lan_ip":lan_ip,"management_ip":mgmt_ip,
                "wireguard_public_key":peer_pub,"steps":steps}
    finally:
        try:
            if target: target.close()
        except Exception: pass
        if hub:
            try: hub.close()
            except Exception: pass



def _site_plan(site, role, lan_ip, name="", reserved=None, node_suffix=None):
    role = str(role or "NODE").upper()
    if role not in ("NODE","PROXY"):
        raise ValueError("Podporovaná role je NODE nebo PROXY.")
    net = ipaddress.ip_network(site["lan_cidr"], strict=False)
    ip = ipaddress.ip_address(lan_ip)
    if ip not in net:
        raise ValueError("LAN IP není v rozsahu lokality "+site["lan_cidr"])
    suffix = int(str(ip).split(".")[-1])
    settings = get_endpoint_settings()
    used_mgmt = {str(v.get("host_ip") or "") for v in settings.values()} | set(reserved or [])
    if role == "PROXY":
        suffix = 9
        generated = site["name"]+"-PROXY"
        if "10.200.%d.9"%site["management_octet"] in used_mgmt: raise ValueError("PROXY .9 už je v lokalitě obsazená.")
    else:
        candidates = [x for x in range(11,30) if "10.200.%d.%d"%(site["management_octet"],x) not in used_mgmt]
        if not candidates: raise ValueError("Lokalita nemá volnou NODE management adresu .11-.29.")
        if node_suffix not in (None, ""):
            try: requested_suffix = int(node_suffix)
            except (TypeError, ValueError): raise ValueError("NODE adresa musí být v rozsahu .11-.29.")
            if requested_suffix < 11 or requested_suffix > 29:
                raise ValueError("NODE adresa musí být v rozsahu .11-.29.")
            requested_mgmt = "10.200.%d.%d" % (site["management_octet"], requested_suffix)
            if requested_mgmt in used_mgmt:
                raise ValueError("NODE management adresa .%d už je v lokalitě obsazená." % requested_suffix)
            suffix = requested_suffix
        else:
            suffix = candidates[0]
        generated = site["name"]+"-NODE"+str(suffix-10).zfill(2)
    mgmt = "10.200.%d.%d" % (site["management_octet"], suffix)
    target_lan = str(ipaddress.ip_address(int(net.network_address)+suffix))
    return {"name": str(name or generated).strip().upper(), "generated_name": generated, "role": role,
            "lan_ip": target_lan, "source_ip": str(ip), "management_ip": mgmt, "data_disk": "AUTO"}

@app.get("/api/provisioning/sites")
async def provisioning_sites(session=Depends(require_permission("admin"))):
    return {"sites": get_sites(), "next_management_octet": next_management_octet()}

@app.post("/api/provisioning/sites")
async def provisioning_site_save(request: Request, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    p=await request.json()
    name=str(p.get("name") or "").strip().upper()
    lan=str(p.get("lan_cidr") or "").strip()
    if not name or not lan: raise HTTPException(400,"Vyplň název a LAN subnet lokality.")
    try:
        net=ipaddress.ip_network(lan,strict=False)
        if net.version!=4: raise ValueError()
        octet=int(p.get("management_octet") or next_management_octet())
        if octet<1 or octet>254: raise ValueError()
        site=save_site(name,str(net),octet,p.get("public_ip") or "",p.get("ssh_user") or "")
    except Exception as exc:
        raise HTTPException(400,"Neplatná nebo kolidující lokalita: "+str(exc))
    return {"site":site}

@app.get("/api/provisioning/discovery/{site_name}")
async def provisioning_discovery(site_name: str, session=Depends(require_permission("admin"))):
    site=get_site(site_name)
    if not site: raise HTTPException(404,"Lokalita neexistuje.")
    net=ipaddress.ip_network(site["lan_cidr"],strict=False)
    if net.num_addresses>256: raise HTTPException(400,"Discovery je omezené na /24 nebo menší subnet.")
    settings=get_endpoint_settings()
    known={str(v.get("lan_ip") or "") for v in settings.values()}
    sem=asyncio.Semaphore(64)
    async def check(ip):
        async with sem:
            try:
                _,w=await asyncio.wait_for(asyncio.open_connection(str(ip),22),0.35)
                w.close()
                try: await w.wait_closed()
                except Exception: pass
                return {"ip":str(ip),"ssh":True,"provisioned":str(ip) in known}
            except Exception: return None
    found=await asyncio.gather(*(check(ip) for ip in net.hosts()))
    return {"site":site,"hosts":[x for x in found if x]}

@app.post("/api/provisioning/identify")
async def provisioning_identify(request: Request, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    p=await request.json();hosts=p.get("hosts") or [];user=str(p.get("ssh_user") or "").strip();password=str(p.get("ssh_password") or "")
    if not user or not password: raise HTTPException(400,"Chybí SSH přihlášení.")
    async def identify(host):
        def run():
            c=_ssh(str(host),22,user,password)
            try: return _run(c,"hostnamectl --static 2>/dev/null || hostname").strip()
            finally: c.close()
        try: return {"ip":str(host),"hostname":await asyncio.to_thread(run)}
        except Exception as exc: return {"ip":str(host),"hostname":"","error":str(exc)}
    return {"hosts":await asyncio.gather(*(identify(h) for h in hosts[:64]))}

@app.post("/api/provisioning/disks")
async def provisioning_disks(request: Request, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    p=await request.json();host=str(p.get("host") or "").strip();user=str(p.get("ssh_user") or "").strip();password=str(p.get("ssh_password") or "")
    if not host or not user or not password: raise HTTPException(400,"Chybí SSH údaje.")
    def inspect():
        c=_ssh(host,22,user,password)
        try:
            out=_run(c,"""ROOT_SRC=$(findmnt -no SOURCE /); ROOT_DISK=$(lsblk -s -npo NAME,TYPE "$ROOT_SRC" | awk '$2=="disk"{print $1;exit}'); while read -r DEV TYPE SIZE; do [ "$TYPE" = disk ] || continue; [ "$DEV" = "$ROOT_DISK" ] && continue; [ -n "$(lsblk -nrpo MOUNTPOINTS "$DEV" | tr -d '[:space:]')" ] && continue; [ -n "$(lsblk -nrpo FSTYPE "$DEV" | tr -d '[:space:]')" ] && continue; echo "$DEV|$SIZE"; done < <(lsblk -dpno NAME,TYPE,SIZE)""")
            return [{"device":line.split("|",1)[0],"size":line.split("|",1)[1] if "|" in line else ""} for line in out.splitlines() if line.strip()]
        finally: c.close()
    try: disks=await asyncio.to_thread(inspect)
    except Exception as exc: raise HTTPException(502,"Kontrola disků selhala: "+str(exc))
    return {"disks":disks}

@app.post("/api/provisioning/plan")
async def provisioning_plan(request: Request, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    p=await request.json();site=get_site(p.get("site"))
    if not site: raise HTTPException(404,"Lokalita neexistuje.")
    try: plan=_site_plan(site,p.get("role"),p.get("lan_ip"),p.get("name") or "",p.get("reserved_management_ips") or [],p.get("node_suffix"))
    except Exception as exc: raise HTTPException(400,str(exc))
    plan.update({"site":site["name"],"public_ip":site.get("public_ip") or "","ssh_user":site.get("ssh_user") or ""})
    return plan

def _hydrate_v2_payload(payload):
    site=get_site(payload.get("site"))
    if not site: return payload
    plan=_site_plan(site,payload.get("role"),payload.get("host") or payload.get("lan_ip"),payload.get("name") or "",node_suffix=payload.get("node_suffix"))
    p=dict(payload);p.update(plan)
    p["site"]=site["name"];p["public_ip"]=site.get("public_ip") or ""
    p["ssh_user"]=str(p.get("ssh_user") or site.get("ssh_user") or "")
    p["hub_host"]=str(p.get("hub_host") or setting_get("provisioning_hub_host", setting_get("wg_hub_lan_ip",""))).strip()
    p["hub_ssh_user"]=str(p.get("hub_ssh_user") or setting_get("provisioning_hub_ssh_user", p.get("ssh_user") or "")).strip()
    p["hub_endpoint"]=str(p.get("hub_endpoint") or setting_get("provisioning_hub_endpoint", setting_get("wg_hub_endpoint",""))).strip()
    if p["hub_ssh_user"]: setting_set("provisioning_hub_ssh_user", p["hub_ssh_user"])
    return p

PROVISION_STEPS = [
    ("ssh","SSH připojení"), ("preflight","Pre-flight kontrola"), ("lan","LAN konfigurace"), ("hostname","Hostname"),
    ("wg_key","WireGuard klíče"), ("wg_peer","Registrace peeru na MAIN"),
    ("wg_start","Spuštění WireGuardu"), ("wg_handshake","WireGuard handshake"),
    ("wg_forward","WireGuard forwarding"), ("data_disk","DATA disk /srv"),
    ("docker","Docker + Portainer Agent"), ("proxy","Traefik PROXY"), ("firewall","Management firewall"),
    ("main_test","MAIN → Portainer Agent"), ("portainer","Registrace v Portaineru")
]

@app.post("/api/provisioning/server/stream")
async def provision_server_stream(request: Request, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")):
        raise HTTPException(403,"Permission denied")
    payload=_hydrate_v2_payload(await request.json())
    q=queue.Queue()
    loop=asyncio.get_running_loop()
    def emit(step,status="done",detail=""):
        q.put({"type":"progress","step":step,"status":status,"detail":detail})
    def worker():
        try:
            result=_provision(payload,emit)
            q.put({"type":"core_done","result":result})
        except Exception as exc:
            q.put({"type":"error","detail":"Provisioning selhal: "+str(exc)})
    import threading
    threading.Thread(target=worker,daemon=True).start()

    async def events():
        result=None
        while True:
            item=await loop.run_in_executor(None,q.get)
            if item["type"]=="core_done":
                result=item["result"]
                break
            yield json.dumps(item,ensure_ascii=False)+"\n"
            if item["type"]=="error":
                return
        try:
            yield json.dumps({"type":"progress","step":"portainer","status":"running","detail":"Registruji environment v Portaineru…"},ensure_ascii=False)+"\n"
            async with client() as cc:
                r=await cc.post("/api/endpoints",data={"Name":result["name"],"EndpointCreationType":"2","URL":"tcp://"+result["management_ip"]+":9001","TLS":"true","TLSSkipVerify":"true","TLSSkipClientVerify":"true"})
            if r.status_code not in (200,201,409):
                yield json.dumps({"type":"error","step":"portainer","detail":"Portainer registration failed: "+r.text},ensure_ascii=False)+"\n"; return
            detail="Portainer environment registered" if r.status_code in (200,201) else "Portainer environment already exists"
            endpoint_id=(r.json() or {}).get("Id") if r.status_code in (200,201) else None
            if endpoint_id is None:
                async with client() as ec:
                    er=await ec.get("/api/endpoints")
                if er.status_code==200:
                    match=next((e for e in er.json() if str(e.get("Name") or "").upper()==str(result["name"]).upper()),None)
                    endpoint_id=(match or {}).get("Id")
            if endpoint_id is None:
                yield json.dumps({"type":"error","step":"portainer","detail":"Portainer endpoint existuje, ale nepodařilo se zjistit jeho ID pro uložení nastavení."},ensure_ascii=False)+"\n"; return
            # Repair mode: an existing Portainer endpoint may still point to the old LAN IP.
            # Move it to the WireGuard management address instead of merely accepting HTTP 409.
            if r.status_code == 409:
                async with client() as uc:
                    ur=await uc.put("/api/endpoints/"+str(endpoint_id),json={
                        "Name":result["name"],"URL":"tcp://"+result["management_ip"]+":9001",
                        "TLS":True,"TLSSkipVerify":True,"TLSSkipClientVerify":True
                    })
                if ur.status_code not in (200,204):
                    yield json.dumps({"type":"error","step":"portainer","detail":"Existující Portainer endpoint se nepodařilo přepnout na management IP: "+ur.text},ensure_ascii=False)+"\n"; return
                detail="Portainer environment repaired → "+result["management_ip"]
            result["portainer_endpoint_id"]=endpoint_id
            agent_url="http://"+result["management_ip"]+":9100" if result["role"]=="NODE" else ""
            save_endpoint_setting(endpoint_id, result["role"]=="NODE", result["management_ip"], result["site"], str(payload.get("public_ip") or "").strip(), agent_url, role=result["role"], lan_ip=result["lan_ip"])
            detail += " · nastavení endpointu uloženo"
            result["steps"].append(detail)
            yield json.dumps({"type":"progress","step":"portainer","status":"done","detail":detail},ensure_ascii=False)+"\n"
            yield json.dumps({"type":"result","result":result},ensure_ascii=False)+"\n"
        except Exception as exc:
            yield json.dumps({"type":"error","step":"portainer","detail":"WG je funkční, ale registrace do Portaineru selhala: "+str(exc)},ensure_ascii=False)+"\n"
    from fastapi.responses import StreamingResponse
    return StreamingResponse(events(),media_type="application/x-ndjson",headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.post("/api/provisioning/server")
async def provision_server(request: Request, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")):
        raise HTTPException(403,"Permission denied")
    payload=_hydrate_v2_payload(await request.json())
    try:
        result=await asyncio.to_thread(_provision,payload)
    except Exception as exc:
        raise HTTPException(502,"Provisioning selhal: "+str(exc))
    # Register Portainer Agent only after WG and firewall have been verified.
    try:
        async with client() as c:
            r=await c.post("/api/endpoints",data={"Name":result["name"],"EndpointCreationType":"2","URL":"tcp://"+result["management_ip"]+":9001","TLS":"true","TLSSkipVerify":"true","TLSSkipClientVerify":"true"})
        if r.status_code not in (200,201,409):
            raise HTTPException(r.status_code,"Portainer registration failed: "+r.text)
        endpoint_id=(r.json() or {}).get("Id") if r.status_code in (200,201) else None
        if endpoint_id is None:
            async with client() as ec:
                er=await ec.get("/api/endpoints")
            if er.status_code==200:
                match=next((e for e in er.json() if str(e.get("Name") or "").upper()==str(result["name"]).upper()),None)
                endpoint_id=(match or {}).get("Id")
        if endpoint_id is None:
            raise HTTPException(502,"Portainer endpoint existuje, ale nepodařilo se zjistit jeho ID pro uložení nastavení.")
        if r.status_code == 409:
            async with client() as uc:
                ur=await uc.put("/api/endpoints/"+str(endpoint_id),json={
                    "Name":result["name"],"URL":"tcp://"+result["management_ip"]+":9001",
                    "TLS":True,"TLSSkipVerify":True,"TLSSkipClientVerify":True
                })
            if ur.status_code not in (200,204):
                raise HTTPException(502,"Existující Portainer endpoint se nepodařilo přepnout na management IP: "+ur.text)
        result["portainer_endpoint_id"]=endpoint_id
        agent_url="http://"+result["management_ip"]+":9100" if result["role"]=="NODE" else ""
        save_endpoint_setting(endpoint_id, result["role"]=="NODE", result["management_ip"], result["site"], str(payload.get("public_ip") or "").strip(), agent_url, role=result["role"], lan_ip=result["lan_ip"])
        result["steps"].append(("Portainer environment registered" if r.status_code in (200,201) else "Portainer environment already exists")+" · nastavení endpointu uloženo")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502,"WG je funkční, ale registrace do Portaineru selhala: "+str(exc))
    return result
; then
  echo "Docker volumes already on DATA /srv"
else
  echo "Existing NODE: Docker volumes relocation deferred to explicit maintenance to avoid workload interruption"
fi"""
            else:
                volume_setup = """systemctl stop docker
mkdir -p /srv/docker-volumes /var/lib/docker/volumes
cp -a /var/lib/docker/volumes/. /srv/docker-volumes/
grep -qE '^[^#]+[[:space:]]+/var/lib/docker/volumes[[:space:]]+none[[:space:]]+bind([,[:space:]]|$)' /etc/fstab || echo '/srv/docker-volumes /var/lib/docker/volumes none bind 0 0' >> /etc/fstab
mountpoint -q /var/lib/docker/volumes || mount /var/lib/docker/volumes
findmnt -rn -T /var/lib/docker/volumes -o TARGET,SOURCE | grep -q '^/var/lib/docker/volumes /srv/docker-volumes
        if role == "PROXY":
            progress("proxy","running","Instaluji/opravuji Traefik reverse proxy…")
            proxycmd = """install -d -m 755 /opt/traefik/dynamic /opt/traefik/letsencrypt /opt/traefik/config
touch /opt/traefik/letsencrypt/acme.json
chmod 600 /opt/traefik/letsencrypt/acme.json
cat >/opt/traefik/config/traefik.yml <<'DSMTRAEFIK'
api:
  dashboard: false
entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"
providers:
  file:
    directory: /etc/traefik/dynamic
    watch: true
certificatesResolvers:
  letsencrypt:
    acme:
      storage: /letsencrypt/acme.json
      httpChallenge:
        entryPoint: web
log:
  level: INFO
DSMTRAEFIK
cat >/opt/traefik/compose.yaml <<'DSMCOMPOSE'
services:
  traefik:
    image: traefik:v3.7
    container_name: traefik
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /opt/traefik/config/traefik.yml:/etc/traefik/traefik.yml:ro
      - /opt/traefik/dynamic:/etc/traefik/dynamic:ro
      - /opt/traefik/letsencrypt:/letsencrypt
DSMCOMPOSE
cd /opt/traefik
docker compose pull
docker compose up -d
for i in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Running}}' traefik 2>/dev/null || true)" = true ] && break
  sleep 1
done
[ "$(docker inspect -f '{{.State.Running}}' traefik 2>/dev/null || true)" = true ]
docker exec traefik traefik healthcheck >/dev/null 2>&1 || docker exec traefik traefik version >/dev/null
test -d /opt/traefik/dynamic
ss -lnt | grep -Eq '[:.]80[[:space:]]'
ss -lnt | grep -Eq '[:.]443[[:space:]]'"""
            _run(target,proxycmd,password,900)
            steps.append("Traefik PROXY OK"); progress("proxy","done","Traefik běží · dynamic config OK · porty 80/443 naslouchají")
        else:
            progress("proxy","done","Role NODE · Traefik se neinstaluje")
        progress("firewall","running","Aplikuji management firewall…")
        fw=f"""# Keep DSM firewall isolated from the host-wide nftables service.
# Loading /etc/nftables.conf can contain 'flush ruleset', which destroys Docker's
# DOCKER-* chains while dockerd is still running. Persist only our own table.
mkdir -p /etc/dockerstackmover
cat >/etc/dockerstackmover/firewall.nft <<'DSMFW'
table inet dockerstackmover-bootstrap {{
 chain input {{
  type filter hook input priority -10; policy accept;
  ct state established,related accept
  iifname lo accept
  iifname "wg-dsm" ip saddr {hub_mgmt_ip} tcp dport 9001 accept
  iifname "wg-dsm" ip saddr {manager_mgmt_ip} tcp dport 9100 accept
  tcp dport {{ 9001, 9100 }} drop
 }}
}}
DSMFW
nft -c -f /etc/dockerstackmover/firewall.nft
nft delete table inet dockerstackmover-bootstrap >/dev/null 2>&1 || true
nft -f /etc/dockerstackmover/firewall.nft
cat >/etc/systemd/system/dockerstackmover-firewall.service <<'DSMSVC'
[Unit]
Description=DockerStackMover management firewall
After=network-online.target docker.service
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c '/usr/sbin/nft delete table inet dockerstackmover-bootstrap >/dev/null 2>&1 || true; /usr/sbin/nft -f /etc/dockerstackmover/firewall.nft'
[Install]
WantedBy=multi-user.target
DSMSVC
systemctl daemon-reload
systemctl enable dockerstackmover-firewall.service
# Remove only the legacy DSM include/file; never reload the host-wide ruleset.
rm -f /etc/nftables.d/dockerstackmover-bootstrap.nft
sed -i '\\|include "/etc/nftables.d/\\*.nft"|d' /etc/nftables.conf 2>/dev/null || true
iptables -t filter -S DOCKER-FORWARD >/dev/null
docker port portainer_agent 9001/tcp | grep -q 9001"""
        _run(target,fw,password)
        steps.append("Management firewall OK"); progress("firewall","done","Management firewall OK")
        # Test the exact central management path before returning success.
        progress("main_test","running","Testuji MAIN → management IP :9001…")
        _run(hub,f"timeout 4 bash -lc '</dev/tcp/{mgmt_ip}/9001'")
        steps.append("MAIN -> "+mgmt_ip+":9001 OK"); progress("main_test","done","MAIN -> "+mgmt_ip+":9001 OK")
        return {"ok":True,"name":name,"site":site,"role":role,"lan_ip":lan_ip,"management_ip":mgmt_ip,
                "wireguard_public_key":peer_pub,"steps":steps}
    finally:
        try:
            if target: target.close()
        except Exception: pass
        if hub:
            try: hub.close()
            except Exception: pass



def _site_plan(site, role, lan_ip, name="", reserved=None, node_suffix=None):
    role = str(role or "NODE").upper()
    if role not in ("NODE","PROXY"):
        raise ValueError("Podporovaná role je NODE nebo PROXY.")
    net = ipaddress.ip_network(site["lan_cidr"], strict=False)
    ip = ipaddress.ip_address(lan_ip)
    if ip not in net:
        raise ValueError("LAN IP není v rozsahu lokality "+site["lan_cidr"])
    suffix = int(str(ip).split(".")[-1])
    settings = get_endpoint_settings()
    used_mgmt = {str(v.get("host_ip") or "") for v in settings.values()} | set(reserved or [])
    if role == "PROXY":
        suffix = 9
        generated = site["name"]+"-PROXY"
        if "10.200.%d.9"%site["management_octet"] in used_mgmt: raise ValueError("PROXY .9 už je v lokalitě obsazená.")
    else:
        candidates = [x for x in range(11,30) if "10.200.%d.%d"%(site["management_octet"],x) not in used_mgmt]
        if not candidates: raise ValueError("Lokalita nemá volnou NODE management adresu .11-.29.")
        if node_suffix not in (None, ""):
            try: requested_suffix = int(node_suffix)
            except (TypeError, ValueError): raise ValueError("NODE adresa musí být v rozsahu .11-.29.")
            if requested_suffix < 11 or requested_suffix > 29:
                raise ValueError("NODE adresa musí být v rozsahu .11-.29.")
            requested_mgmt = "10.200.%d.%d" % (site["management_octet"], requested_suffix)
            if requested_mgmt in used_mgmt:
                raise ValueError("NODE management adresa .%d už je v lokalitě obsazená." % requested_suffix)
            suffix = requested_suffix
        else:
            suffix = candidates[0]
        generated = site["name"]+"-NODE"+str(suffix-10).zfill(2)
    mgmt = "10.200.%d.%d" % (site["management_octet"], suffix)
    target_lan = str(ipaddress.ip_address(int(net.network_address)+suffix))
    return {"name": str(name or generated).strip().upper(), "generated_name": generated, "role": role,
            "lan_ip": target_lan, "source_ip": str(ip), "management_ip": mgmt, "data_disk": "AUTO"}

@app.get("/api/provisioning/sites")
async def provisioning_sites(session=Depends(require_permission("admin"))):
    return {"sites": get_sites(), "next_management_octet": next_management_octet()}

@app.post("/api/provisioning/sites")
async def provisioning_site_save(request: Request, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    p=await request.json()
    name=str(p.get("name") or "").strip().upper()
    lan=str(p.get("lan_cidr") or "").strip()
    if not name or not lan: raise HTTPException(400,"Vyplň název a LAN subnet lokality.")
    try:
        net=ipaddress.ip_network(lan,strict=False)
        if net.version!=4: raise ValueError()
        octet=int(p.get("management_octet") or next_management_octet())
        if octet<1 or octet>254: raise ValueError()
        site=save_site(name,str(net),octet,p.get("public_ip") or "",p.get("ssh_user") or "")
    except Exception as exc:
        raise HTTPException(400,"Neplatná nebo kolidující lokalita: "+str(exc))
    return {"site":site}

@app.get("/api/provisioning/discovery/{site_name}")
async def provisioning_discovery(site_name: str, session=Depends(require_permission("admin"))):
    site=get_site(site_name)
    if not site: raise HTTPException(404,"Lokalita neexistuje.")
    net=ipaddress.ip_network(site["lan_cidr"],strict=False)
    if net.num_addresses>256: raise HTTPException(400,"Discovery je omezené na /24 nebo menší subnet.")
    settings=get_endpoint_settings()
    known={str(v.get("lan_ip") or "") for v in settings.values()}
    sem=asyncio.Semaphore(64)
    async def check(ip):
        async with sem:
            try:
                _,w=await asyncio.wait_for(asyncio.open_connection(str(ip),22),0.35)
                w.close()
                try: await w.wait_closed()
                except Exception: pass
                return {"ip":str(ip),"ssh":True,"provisioned":str(ip) in known}
            except Exception: return None
    found=await asyncio.gather(*(check(ip) for ip in net.hosts()))
    return {"site":site,"hosts":[x for x in found if x]}

@app.post("/api/provisioning/identify")
async def provisioning_identify(request: Request, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    p=await request.json();hosts=p.get("hosts") or [];user=str(p.get("ssh_user") or "").strip();password=str(p.get("ssh_password") or "")
    if not user or not password: raise HTTPException(400,"Chybí SSH přihlášení.")
    async def identify(host):
        def run():
            c=_ssh(str(host),22,user,password)
            try: return _run(c,"hostnamectl --static 2>/dev/null || hostname").strip()
            finally: c.close()
        try: return {"ip":str(host),"hostname":await asyncio.to_thread(run)}
        except Exception as exc: return {"ip":str(host),"hostname":"","error":str(exc)}
    return {"hosts":await asyncio.gather(*(identify(h) for h in hosts[:64]))}

@app.post("/api/provisioning/disks")
async def provisioning_disks(request: Request, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    p=await request.json();host=str(p.get("host") or "").strip();user=str(p.get("ssh_user") or "").strip();password=str(p.get("ssh_password") or "")
    if not host or not user or not password: raise HTTPException(400,"Chybí SSH údaje.")
    def inspect():
        c=_ssh(host,22,user,password)
        try:
            out=_run(c,"""ROOT_SRC=$(findmnt -no SOURCE /); ROOT_DISK=$(lsblk -s -npo NAME,TYPE "$ROOT_SRC" | awk '$2=="disk"{print $1;exit}'); while read -r DEV TYPE SIZE; do [ "$TYPE" = disk ] || continue; [ "$DEV" = "$ROOT_DISK" ] && continue; [ -n "$(lsblk -nrpo MOUNTPOINTS "$DEV" | tr -d '[:space:]')" ] && continue; [ -n "$(lsblk -nrpo FSTYPE "$DEV" | tr -d '[:space:]')" ] && continue; echo "$DEV|$SIZE"; done < <(lsblk -dpno NAME,TYPE,SIZE)""")
            return [{"device":line.split("|",1)[0],"size":line.split("|",1)[1] if "|" in line else ""} for line in out.splitlines() if line.strip()]
        finally: c.close()
    try: disks=await asyncio.to_thread(inspect)
    except Exception as exc: raise HTTPException(502,"Kontrola disků selhala: "+str(exc))
    return {"disks":disks}

@app.post("/api/provisioning/plan")
async def provisioning_plan(request: Request, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    p=await request.json();site=get_site(p.get("site"))
    if not site: raise HTTPException(404,"Lokalita neexistuje.")
    try: plan=_site_plan(site,p.get("role"),p.get("lan_ip"),p.get("name") or "",p.get("reserved_management_ips") or [],p.get("node_suffix"))
    except Exception as exc: raise HTTPException(400,str(exc))
    plan.update({"site":site["name"],"public_ip":site.get("public_ip") or "","ssh_user":site.get("ssh_user") or ""})
    return plan

def _hydrate_v2_payload(payload):
    site=get_site(payload.get("site"))
    if not site: return payload
    plan=_site_plan(site,payload.get("role"),payload.get("host") or payload.get("lan_ip"),payload.get("name") or "",node_suffix=payload.get("node_suffix"))
    p=dict(payload);p.update(plan)
    p["site"]=site["name"];p["public_ip"]=site.get("public_ip") or ""
    p["ssh_user"]=str(p.get("ssh_user") or site.get("ssh_user") or "")
    p["hub_host"]=str(p.get("hub_host") or setting_get("provisioning_hub_host", setting_get("wg_hub_lan_ip",""))).strip()
    p["hub_ssh_user"]=str(p.get("hub_ssh_user") or setting_get("provisioning_hub_ssh_user", p.get("ssh_user") or "")).strip()
    p["hub_endpoint"]=str(p.get("hub_endpoint") or setting_get("provisioning_hub_endpoint", setting_get("wg_hub_endpoint",""))).strip()
    if p["hub_ssh_user"]: setting_set("provisioning_hub_ssh_user", p["hub_ssh_user"])
    return p

PROVISION_STEPS = [
    ("ssh","SSH připojení"), ("preflight","Pre-flight kontrola"), ("lan","LAN konfigurace"), ("hostname","Hostname"),
    ("wg_key","WireGuard klíče"), ("wg_peer","Registrace peeru na MAIN"),
    ("wg_start","Spuštění WireGuardu"), ("wg_handshake","WireGuard handshake"),
    ("wg_forward","WireGuard forwarding"), ("data_disk","DATA disk /srv"),
    ("docker","Docker + Portainer Agent"), ("proxy","Traefik PROXY"), ("firewall","Management firewall"),
    ("main_test","MAIN → Portainer Agent"), ("portainer","Registrace v Portaineru")
]

@app.post("/api/provisioning/server/stream")
async def provision_server_stream(request: Request, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")):
        raise HTTPException(403,"Permission denied")
    payload=_hydrate_v2_payload(await request.json())
    q=queue.Queue()
    loop=asyncio.get_running_loop()
    def emit(step,status="done",detail=""):
        q.put({"type":"progress","step":step,"status":status,"detail":detail})
    def worker():
        try:
            result=_provision(payload,emit)
            q.put({"type":"core_done","result":result})
        except Exception as exc:
            q.put({"type":"error","detail":"Provisioning selhal: "+str(exc)})
    import threading
    threading.Thread(target=worker,daemon=True).start()

    async def events():
        result=None
        while True:
            item=await loop.run_in_executor(None,q.get)
            if item["type"]=="core_done":
                result=item["result"]
                break
            yield json.dumps(item,ensure_ascii=False)+"\n"
            if item["type"]=="error":
                return
        try:
            yield json.dumps({"type":"progress","step":"portainer","status":"running","detail":"Registruji environment v Portaineru…"},ensure_ascii=False)+"\n"
            async with client() as cc:
                r=await cc.post("/api/endpoints",data={"Name":result["name"],"EndpointCreationType":"2","URL":"tcp://"+result["management_ip"]+":9001","TLS":"true","TLSSkipVerify":"true","TLSSkipClientVerify":"true"})
            if r.status_code not in (200,201,409):
                yield json.dumps({"type":"error","step":"portainer","detail":"Portainer registration failed: "+r.text},ensure_ascii=False)+"\n"; return
            detail="Portainer environment registered" if r.status_code in (200,201) else "Portainer environment already exists"
            endpoint_id=(r.json() or {}).get("Id") if r.status_code in (200,201) else None
            if endpoint_id is None:
                async with client() as ec:
                    er=await ec.get("/api/endpoints")
                if er.status_code==200:
                    match=next((e for e in er.json() if str(e.get("Name") or "").upper()==str(result["name"]).upper()),None)
                    endpoint_id=(match or {}).get("Id")
            if endpoint_id is None:
                yield json.dumps({"type":"error","step":"portainer","detail":"Portainer endpoint existuje, ale nepodařilo se zjistit jeho ID pro uložení nastavení."},ensure_ascii=False)+"\n"; return
            # Repair mode: an existing Portainer endpoint may still point to the old LAN IP.
            # Move it to the WireGuard management address instead of merely accepting HTTP 409.
            if r.status_code == 409:
                async with client() as uc:
                    ur=await uc.put("/api/endpoints/"+str(endpoint_id),json={
                        "Name":result["name"],"URL":"tcp://"+result["management_ip"]+":9001",
                        "TLS":True,"TLSSkipVerify":True,"TLSSkipClientVerify":True
                    })
                if ur.status_code not in (200,204):
                    yield json.dumps({"type":"error","step":"portainer","detail":"Existující Portainer endpoint se nepodařilo přepnout na management IP: "+ur.text},ensure_ascii=False)+"\n"; return
                detail="Portainer environment repaired → "+result["management_ip"]
            result["portainer_endpoint_id"]=endpoint_id
            agent_url="http://"+result["management_ip"]+":9100" if result["role"]=="NODE" else ""
            save_endpoint_setting(endpoint_id, result["role"]=="NODE", result["management_ip"], result["site"], str(payload.get("public_ip") or "").strip(), agent_url, role=result["role"], lan_ip=result["lan_ip"])
            detail += " · nastavení endpointu uloženo"
            result["steps"].append(detail)
            yield json.dumps({"type":"progress","step":"portainer","status":"done","detail":detail},ensure_ascii=False)+"\n"
            yield json.dumps({"type":"result","result":result},ensure_ascii=False)+"\n"
        except Exception as exc:
            yield json.dumps({"type":"error","step":"portainer","detail":"WG je funkční, ale registrace do Portaineru selhala: "+str(exc)},ensure_ascii=False)+"\n"
    from fastapi.responses import StreamingResponse
    return StreamingResponse(events(),media_type="application/x-ndjson",headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.post("/api/provisioning/server")
async def provision_server(request: Request, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")):
        raise HTTPException(403,"Permission denied")
    payload=_hydrate_v2_payload(await request.json())
    try:
        result=await asyncio.to_thread(_provision,payload)
    except Exception as exc:
        raise HTTPException(502,"Provisioning selhal: "+str(exc))
    # Register Portainer Agent only after WG and firewall have been verified.
    try:
        async with client() as c:
            r=await c.post("/api/endpoints",data={"Name":result["name"],"EndpointCreationType":"2","URL":"tcp://"+result["management_ip"]+":9001","TLS":"true","TLSSkipVerify":"true","TLSSkipClientVerify":"true"})
        if r.status_code not in (200,201,409):
            raise HTTPException(r.status_code,"Portainer registration failed: "+r.text)
        endpoint_id=(r.json() or {}).get("Id") if r.status_code in (200,201) else None
        if endpoint_id is None:
            async with client() as ec:
                er=await ec.get("/api/endpoints")
            if er.status_code==200:
                match=next((e for e in er.json() if str(e.get("Name") or "").upper()==str(result["name"]).upper()),None)
                endpoint_id=(match or {}).get("Id")
        if endpoint_id is None:
            raise HTTPException(502,"Portainer endpoint existuje, ale nepodařilo se zjistit jeho ID pro uložení nastavení.")
        if r.status_code == 409:
            async with client() as uc:
                ur=await uc.put("/api/endpoints/"+str(endpoint_id),json={
                    "Name":result["name"],"URL":"tcp://"+result["management_ip"]+":9001",
                    "TLS":True,"TLSSkipVerify":True,"TLSSkipClientVerify":True
                })
            if ur.status_code not in (200,204):
                raise HTTPException(502,"Existující Portainer endpoint se nepodařilo přepnout na management IP: "+ur.text)
        result["portainer_endpoint_id"]=endpoint_id
        agent_url="http://"+result["management_ip"]+":9100" if result["role"]=="NODE" else ""
        save_endpoint_setting(endpoint_id, result["role"]=="NODE", result["management_ip"], result["site"], str(payload.get("public_ip") or "").strip(), agent_url, role=result["role"], lan_ip=result["lan_ip"])
        result["steps"].append(("Portainer environment registered" if r.status_code in (200,201) else "Portainer environment already exists")+" · nastavení endpointu uloženo")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502,"WG je funkční, ale registrace do Portaineru selhala: "+str(exc))
    return result

systemctl start docker"""
        else:
            volume_setup = ":"
        docker = docker.replace("__NODE_VOLUME_SETUP__", volume_setup)
        _run(target,docker,password,900)
        steps.append("Docker + Portainer Agent OK"); progress("docker","done","Docker + Portainer Agent OK")
        if role == "PROXY":
            progress("proxy","running","Instaluji/opravuji Traefik reverse proxy…")
            proxycmd = """install -d -m 755 /opt/traefik/dynamic /opt/traefik/letsencrypt /opt/traefik/config
touch /opt/traefik/letsencrypt/acme.json
chmod 600 /opt/traefik/letsencrypt/acme.json
cat >/opt/traefik/config/traefik.yml <<'DSMTRAEFIK'
api:
  dashboard: false
entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"
providers:
  file:
    directory: /etc/traefik/dynamic
    watch: true
certificatesResolvers:
  letsencrypt:
    acme:
      storage: /letsencrypt/acme.json
      httpChallenge:
        entryPoint: web
log:
  level: INFO
DSMTRAEFIK
cat >/opt/traefik/compose.yaml <<'DSMCOMPOSE'
services:
  traefik:
    image: traefik:v3.7
    container_name: traefik
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /opt/traefik/config/traefik.yml:/etc/traefik/traefik.yml:ro
      - /opt/traefik/dynamic:/etc/traefik/dynamic:ro
      - /opt/traefik/letsencrypt:/letsencrypt
DSMCOMPOSE
cd /opt/traefik
docker compose pull
docker compose up -d
for i in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Running}}' traefik 2>/dev/null || true)" = true ] && break
  sleep 1
done
[ "$(docker inspect -f '{{.State.Running}}' traefik 2>/dev/null || true)" = true ]
docker exec traefik traefik healthcheck >/dev/null 2>&1 || docker exec traefik traefik version >/dev/null
test -d /opt/traefik/dynamic
ss -lnt | grep -Eq '[:.]80[[:space:]]'
ss -lnt | grep -Eq '[:.]443[[:space:]]'"""
            _run(target,proxycmd,password,900)
            steps.append("Traefik PROXY OK"); progress("proxy","done","Traefik běží · dynamic config OK · porty 80/443 naslouchají")
        else:
            progress("proxy","done","Role NODE · Traefik se neinstaluje")
        progress("firewall","running","Aplikuji management firewall…")
        fw=f"""# Keep DSM firewall isolated from the host-wide nftables service.
# Loading /etc/nftables.conf can contain 'flush ruleset', which destroys Docker's
# DOCKER-* chains while dockerd is still running. Persist only our own table.
mkdir -p /etc/dockerstackmover
cat >/etc/dockerstackmover/firewall.nft <<'DSMFW'
table inet dockerstackmover-bootstrap {{
 chain input {{
  type filter hook input priority -10; policy accept;
  ct state established,related accept
  iifname lo accept
  iifname "wg-dsm" ip saddr {hub_mgmt_ip} tcp dport 9001 accept
  iifname "wg-dsm" ip saddr {manager_mgmt_ip} tcp dport 9100 accept
  tcp dport {{ 9001, 9100 }} drop
 }}
}}
DSMFW
nft -c -f /etc/dockerstackmover/firewall.nft
nft delete table inet dockerstackmover-bootstrap >/dev/null 2>&1 || true
nft -f /etc/dockerstackmover/firewall.nft
cat >/etc/systemd/system/dockerstackmover-firewall.service <<'DSMSVC'
[Unit]
Description=DockerStackMover management firewall
After=network-online.target docker.service
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c '/usr/sbin/nft delete table inet dockerstackmover-bootstrap >/dev/null 2>&1 || true; /usr/sbin/nft -f /etc/dockerstackmover/firewall.nft'
[Install]
WantedBy=multi-user.target
DSMSVC
systemctl daemon-reload
systemctl enable dockerstackmover-firewall.service
# Remove only the legacy DSM include/file; never reload the host-wide ruleset.
rm -f /etc/nftables.d/dockerstackmover-bootstrap.nft
sed -i '\\|include "/etc/nftables.d/\\*.nft"|d' /etc/nftables.conf 2>/dev/null || true
iptables -t filter -S DOCKER-FORWARD >/dev/null
docker port portainer_agent 9001/tcp | grep -q 9001"""
        _run(target,fw,password)
        steps.append("Management firewall OK"); progress("firewall","done","Management firewall OK")
        # Test the exact central management path before returning success.
        progress("main_test","running","Testuji MAIN → management IP :9001…")
        _run(hub,f"timeout 4 bash -lc '</dev/tcp/{mgmt_ip}/9001'")
        steps.append("MAIN -> "+mgmt_ip+":9001 OK"); progress("main_test","done","MAIN -> "+mgmt_ip+":9001 OK")
        return {"ok":True,"name":name,"site":site,"role":role,"lan_ip":lan_ip,"management_ip":mgmt_ip,
                "wireguard_public_key":peer_pub,"steps":steps}
    finally:
        try:
            if target: target.close()
        except Exception: pass
        if hub:
            try: hub.close()
            except Exception: pass



def _site_plan(site, role, lan_ip, name="", reserved=None, node_suffix=None):
    role = str(role or "NODE").upper()
    if role not in ("NODE","PROXY"):
        raise ValueError("Podporovaná role je NODE nebo PROXY.")
    net = ipaddress.ip_network(site["lan_cidr"], strict=False)
    ip = ipaddress.ip_address(lan_ip)
    if ip not in net:
        raise ValueError("LAN IP není v rozsahu lokality "+site["lan_cidr"])
    suffix = int(str(ip).split(".")[-1])
    settings = get_endpoint_settings()
    used_mgmt = {str(v.get("host_ip") or "") for v in settings.values()} | set(reserved or [])
    if role == "PROXY":
        suffix = 9
        generated = site["name"]+"-PROXY"
        if "10.200.%d.9"%site["management_octet"] in used_mgmt: raise ValueError("PROXY .9 už je v lokalitě obsazená.")
    else:
        candidates = [x for x in range(11,30) if "10.200.%d.%d"%(site["management_octet"],x) not in used_mgmt]
        if not candidates: raise ValueError("Lokalita nemá volnou NODE management adresu .11-.29.")
        if node_suffix not in (None, ""):
            try: requested_suffix = int(node_suffix)
            except (TypeError, ValueError): raise ValueError("NODE adresa musí být v rozsahu .11-.29.")
            if requested_suffix < 11 or requested_suffix > 29:
                raise ValueError("NODE adresa musí být v rozsahu .11-.29.")
            requested_mgmt = "10.200.%d.%d" % (site["management_octet"], requested_suffix)
            if requested_mgmt in used_mgmt:
                raise ValueError("NODE management adresa .%d už je v lokalitě obsazená." % requested_suffix)
            suffix = requested_suffix
        else:
            suffix = candidates[0]
        generated = site["name"]+"-NODE"+str(suffix-10).zfill(2)
    mgmt = "10.200.%d.%d" % (site["management_octet"], suffix)
    target_lan = str(ipaddress.ip_address(int(net.network_address)+suffix))
    return {"name": str(name or generated).strip().upper(), "generated_name": generated, "role": role,
            "lan_ip": target_lan, "source_ip": str(ip), "management_ip": mgmt, "data_disk": "AUTO"}

@app.get("/api/provisioning/sites")
async def provisioning_sites(session=Depends(require_permission("admin"))):
    return {"sites": get_sites(), "next_management_octet": next_management_octet()}

@app.post("/api/provisioning/sites")
async def provisioning_site_save(request: Request, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    p=await request.json()
    name=str(p.get("name") or "").strip().upper()
    lan=str(p.get("lan_cidr") or "").strip()
    if not name or not lan: raise HTTPException(400,"Vyplň název a LAN subnet lokality.")
    try:
        net=ipaddress.ip_network(lan,strict=False)
        if net.version!=4: raise ValueError()
        octet=int(p.get("management_octet") or next_management_octet())
        if octet<1 or octet>254: raise ValueError()
        site=save_site(name,str(net),octet,p.get("public_ip") or "",p.get("ssh_user") or "")
    except Exception as exc:
        raise HTTPException(400,"Neplatná nebo kolidující lokalita: "+str(exc))
    return {"site":site}

@app.get("/api/provisioning/discovery/{site_name}")
async def provisioning_discovery(site_name: str, session=Depends(require_permission("admin"))):
    site=get_site(site_name)
    if not site: raise HTTPException(404,"Lokalita neexistuje.")
    net=ipaddress.ip_network(site["lan_cidr"],strict=False)
    if net.num_addresses>256: raise HTTPException(400,"Discovery je omezené na /24 nebo menší subnet.")
    settings=get_endpoint_settings()
    known={str(v.get("lan_ip") or "") for v in settings.values()}
    sem=asyncio.Semaphore(64)
    async def check(ip):
        async with sem:
            try:
                _,w=await asyncio.wait_for(asyncio.open_connection(str(ip),22),0.35)
                w.close()
                try: await w.wait_closed()
                except Exception: pass
                return {"ip":str(ip),"ssh":True,"provisioned":str(ip) in known}
            except Exception: return None
    found=await asyncio.gather(*(check(ip) for ip in net.hosts()))
    return {"site":site,"hosts":[x for x in found if x]}

@app.post("/api/provisioning/identify")
async def provisioning_identify(request: Request, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    p=await request.json();hosts=p.get("hosts") or [];user=str(p.get("ssh_user") or "").strip();password=str(p.get("ssh_password") or "")
    if not user or not password: raise HTTPException(400,"Chybí SSH přihlášení.")
    async def identify(host):
        def run():
            c=_ssh(str(host),22,user,password)
            try: return _run(c,"hostnamectl --static 2>/dev/null || hostname").strip()
            finally: c.close()
        try: return {"ip":str(host),"hostname":await asyncio.to_thread(run)}
        except Exception as exc: return {"ip":str(host),"hostname":"","error":str(exc)}
    return {"hosts":await asyncio.gather(*(identify(h) for h in hosts[:64]))}

@app.post("/api/provisioning/disks")
async def provisioning_disks(request: Request, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    p=await request.json();host=str(p.get("host") or "").strip();user=str(p.get("ssh_user") or "").strip();password=str(p.get("ssh_password") or "")
    if not host or not user or not password: raise HTTPException(400,"Chybí SSH údaje.")
    def inspect():
        c=_ssh(host,22,user,password)
        try:
            out=_run(c,"""ROOT_SRC=$(findmnt -no SOURCE /); ROOT_DISK=$(lsblk -s -npo NAME,TYPE "$ROOT_SRC" | awk '$2=="disk"{print $1;exit}'); while read -r DEV TYPE SIZE; do [ "$TYPE" = disk ] || continue; [ "$DEV" = "$ROOT_DISK" ] && continue; [ -n "$(lsblk -nrpo MOUNTPOINTS "$DEV" | tr -d '[:space:]')" ] && continue; [ -n "$(lsblk -nrpo FSTYPE "$DEV" | tr -d '[:space:]')" ] && continue; echo "$DEV|$SIZE"; done < <(lsblk -dpno NAME,TYPE,SIZE)""")
            return [{"device":line.split("|",1)[0],"size":line.split("|",1)[1] if "|" in line else ""} for line in out.splitlines() if line.strip()]
        finally: c.close()
    try: disks=await asyncio.to_thread(inspect)
    except Exception as exc: raise HTTPException(502,"Kontrola disků selhala: "+str(exc))
    return {"disks":disks}

@app.post("/api/provisioning/plan")
async def provisioning_plan(request: Request, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")): raise HTTPException(403,"Permission denied")
    p=await request.json();site=get_site(p.get("site"))
    if not site: raise HTTPException(404,"Lokalita neexistuje.")
    try: plan=_site_plan(site,p.get("role"),p.get("lan_ip"),p.get("name") or "",p.get("reserved_management_ips") or [],p.get("node_suffix"))
    except Exception as exc: raise HTTPException(400,str(exc))
    plan.update({"site":site["name"],"public_ip":site.get("public_ip") or "","ssh_user":site.get("ssh_user") or ""})
    return plan

def _hydrate_v2_payload(payload):
    site=get_site(payload.get("site"))
    if not site: return payload
    plan=_site_plan(site,payload.get("role"),payload.get("host") or payload.get("lan_ip"),payload.get("name") or "",node_suffix=payload.get("node_suffix"))
    p=dict(payload);p.update(plan)
    p["site"]=site["name"];p["public_ip"]=site.get("public_ip") or ""
    p["ssh_user"]=str(p.get("ssh_user") or site.get("ssh_user") or "")
    p["hub_host"]=str(p.get("hub_host") or setting_get("provisioning_hub_host", setting_get("wg_hub_lan_ip",""))).strip()
    p["hub_ssh_user"]=str(p.get("hub_ssh_user") or setting_get("provisioning_hub_ssh_user", p.get("ssh_user") or "")).strip()
    p["hub_endpoint"]=str(p.get("hub_endpoint") or setting_get("provisioning_hub_endpoint", setting_get("wg_hub_endpoint",""))).strip()
    if p["hub_ssh_user"]: setting_set("provisioning_hub_ssh_user", p["hub_ssh_user"])
    return p

PROVISION_STEPS = [
    ("ssh","SSH připojení"), ("preflight","Pre-flight kontrola"), ("lan","LAN konfigurace"), ("hostname","Hostname"),
    ("wg_key","WireGuard klíče"), ("wg_peer","Registrace peeru na MAIN"),
    ("wg_start","Spuštění WireGuardu"), ("wg_handshake","WireGuard handshake"),
    ("wg_forward","WireGuard forwarding"), ("data_disk","DATA disk /srv"),
    ("docker","Docker + Portainer Agent"), ("proxy","Traefik PROXY"), ("firewall","Management firewall"),
    ("main_test","MAIN → Portainer Agent"), ("portainer","Registrace v Portaineru")
]

@app.post("/api/provisioning/server/stream")
async def provision_server_stream(request: Request, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")):
        raise HTTPException(403,"Permission denied")
    payload=_hydrate_v2_payload(await request.json())
    q=queue.Queue()
    loop=asyncio.get_running_loop()
    def emit(step,status="done",detail=""):
        q.put({"type":"progress","step":step,"status":status,"detail":detail})
    def worker():
        try:
            result=_provision(payload,emit)
            q.put({"type":"core_done","result":result})
        except Exception as exc:
            q.put({"type":"error","detail":"Provisioning selhal: "+str(exc)})
    import threading
    threading.Thread(target=worker,daemon=True).start()

    async def events():
        result=None
        while True:
            item=await loop.run_in_executor(None,q.get)
            if item["type"]=="core_done":
                result=item["result"]
                break
            yield json.dumps(item,ensure_ascii=False)+"\n"
            if item["type"]=="error":
                return
        try:
            yield json.dumps({"type":"progress","step":"portainer","status":"running","detail":"Registruji environment v Portaineru…"},ensure_ascii=False)+"\n"
            async with client() as cc:
                r=await cc.post("/api/endpoints",data={"Name":result["name"],"EndpointCreationType":"2","URL":"tcp://"+result["management_ip"]+":9001","TLS":"true","TLSSkipVerify":"true","TLSSkipClientVerify":"true"})
            if r.status_code not in (200,201,409):
                yield json.dumps({"type":"error","step":"portainer","detail":"Portainer registration failed: "+r.text},ensure_ascii=False)+"\n"; return
            detail="Portainer environment registered" if r.status_code in (200,201) else "Portainer environment already exists"
            endpoint_id=(r.json() or {}).get("Id") if r.status_code in (200,201) else None
            if endpoint_id is None:
                async with client() as ec:
                    er=await ec.get("/api/endpoints")
                if er.status_code==200:
                    match=next((e for e in er.json() if str(e.get("Name") or "").upper()==str(result["name"]).upper()),None)
                    endpoint_id=(match or {}).get("Id")
            if endpoint_id is None:
                yield json.dumps({"type":"error","step":"portainer","detail":"Portainer endpoint existuje, ale nepodařilo se zjistit jeho ID pro uložení nastavení."},ensure_ascii=False)+"\n"; return
            # Repair mode: an existing Portainer endpoint may still point to the old LAN IP.
            # Move it to the WireGuard management address instead of merely accepting HTTP 409.
            if r.status_code == 409:
                async with client() as uc:
                    ur=await uc.put("/api/endpoints/"+str(endpoint_id),json={
                        "Name":result["name"],"URL":"tcp://"+result["management_ip"]+":9001",
                        "TLS":True,"TLSSkipVerify":True,"TLSSkipClientVerify":True
                    })
                if ur.status_code not in (200,204):
                    yield json.dumps({"type":"error","step":"portainer","detail":"Existující Portainer endpoint se nepodařilo přepnout na management IP: "+ur.text},ensure_ascii=False)+"\n"; return
                detail="Portainer environment repaired → "+result["management_ip"]
            result["portainer_endpoint_id"]=endpoint_id
            agent_url="http://"+result["management_ip"]+":9100" if result["role"]=="NODE" else ""
            save_endpoint_setting(endpoint_id, result["role"]=="NODE", result["management_ip"], result["site"], str(payload.get("public_ip") or "").strip(), agent_url, role=result["role"], lan_ip=result["lan_ip"])
            detail += " · nastavení endpointu uloženo"
            result["steps"].append(detail)
            yield json.dumps({"type":"progress","step":"portainer","status":"done","detail":detail},ensure_ascii=False)+"\n"
            yield json.dumps({"type":"result","result":result},ensure_ascii=False)+"\n"
        except Exception as exc:
            yield json.dumps({"type":"error","step":"portainer","detail":"WG je funkční, ale registrace do Portaineru selhala: "+str(exc)},ensure_ascii=False)+"\n"
    from fastapi.responses import StreamingResponse
    return StreamingResponse(events(),media_type="application/x-ndjson",headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.post("/api/provisioning/server")
async def provision_server(request: Request, session=Depends(require_csrf)):
    if "admin" not in user_permissions(session.get("user","")):
        raise HTTPException(403,"Permission denied")
    payload=_hydrate_v2_payload(await request.json())
    try:
        result=await asyncio.to_thread(_provision,payload)
    except Exception as exc:
        raise HTTPException(502,"Provisioning selhal: "+str(exc))
    # Register Portainer Agent only after WG and firewall have been verified.
    try:
        async with client() as c:
            r=await c.post("/api/endpoints",data={"Name":result["name"],"EndpointCreationType":"2","URL":"tcp://"+result["management_ip"]+":9001","TLS":"true","TLSSkipVerify":"true","TLSSkipClientVerify":"true"})
        if r.status_code not in (200,201,409):
            raise HTTPException(r.status_code,"Portainer registration failed: "+r.text)
        endpoint_id=(r.json() or {}).get("Id") if r.status_code in (200,201) else None
        if endpoint_id is None:
            async with client() as ec:
                er=await ec.get("/api/endpoints")
            if er.status_code==200:
                match=next((e for e in er.json() if str(e.get("Name") or "").upper()==str(result["name"]).upper()),None)
                endpoint_id=(match or {}).get("Id")
        if endpoint_id is None:
            raise HTTPException(502,"Portainer endpoint existuje, ale nepodařilo se zjistit jeho ID pro uložení nastavení.")
        if r.status_code == 409:
            async with client() as uc:
                ur=await uc.put("/api/endpoints/"+str(endpoint_id),json={
                    "Name":result["name"],"URL":"tcp://"+result["management_ip"]+":9001",
                    "TLS":True,"TLSSkipVerify":True,"TLSSkipClientVerify":True
                })
            if ur.status_code not in (200,204):
                raise HTTPException(502,"Existující Portainer endpoint se nepodařilo přepnout na management IP: "+ur.text)
        result["portainer_endpoint_id"]=endpoint_id
        agent_url="http://"+result["management_ip"]+":9100" if result["role"]=="NODE" else ""
        save_endpoint_setting(endpoint_id, result["role"]=="NODE", result["management_ip"], result["site"], str(payload.get("public_ip") or "").strip(), agent_url, role=result["role"], lan_ip=result["lan_ip"])
        result["steps"].append(("Portainer environment registered" if r.status_code in (200,201) else "Portainer environment already exists")+" · nastavení endpointu uloženo")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502,"WG je funkční, ale registrace do Portaineru selhala: "+str(exc))
    return result
