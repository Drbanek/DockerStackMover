#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "[ERROR] řádek $LINENO: $BASH_COMMAND" >&2' ERR
[[ $EUID -eq 0 ]] || { echo "Spusť přes sudo."; exit 1; }

say(){ printf "\n\033[1;36m%s\033[0m\n" "$*"; }
ok(){ printf "  \033[1;32m✓\033[0m %s\n" "$*"; }
die(){ echo "CHYBA: $*" >&2; exit 1; }
ask(){ local __v=$1 __p=$2 __d=${3:-}; local x; read -rp "$__p${__d:+ [$__d]}: " x; printf -v "$__v" '%s' "${x:-$__d}"; }

source /etc/os-release
[[ "${ID:-}" == ubuntu ]] || die "Podporováno je Ubuntu Server."
say "DockerStackMover v2.1 · Server Bootstrap"
echo "Adresní pravidla: CONTROL/MGMT=.9  PROXY=.10  NODE=.11-.29"

DEF_IF=$(ip -4 route show default | awk 'NR==1{print $5}')
[[ -n "$DEF_IF" ]] || die "Nelze zjistit síťové rozhraní."
CIDR=$(ip -o -4 addr show dev "$DEF_IF" scope global | awk 'NR==1{print $4}')
GW=$(ip -4 route show default | awk 'NR==1{print $3}')
[[ -n "$CIDR" && -n "$GW" ]] || die "Nelze zjistit IPv4/gateway."
PREFIX=${CIDR#*/}
CUR_IP=${CIDR%/*}
[[ "$PREFIX" == 24 ]] || die "Automatické LAN adresování v1.13 podporuje /24; zjištěno /$PREFIX."
BASE=$(awk -F. '{print $1"."$2"."$3}' <<<"$CUR_IP")

ask SITE "Označení lokality (např. DC1, DC2, PRAHA, PLZEN)" ""
[[ -n "$SITE" ]] || die "Označení lokality je povinné."
SITE=${SITE^^}
echo "Role: 1=PROXY  2=NODE  3=CONTROL/MGMT (MAIN)"
read -rp "Vyber roli: " ROLE_N
case "$ROLE_N" in
  1) ROLE=PROXY; LAST=10; HOSTNAME_NEW="${SITE}-PROXY" ;;
  2) ROLE=NODE
     while :; do read -rp "NODE adresa .11-.29: " LAST; [[ "$LAST" =~ ^(1[1-9]|2[0-9])$ ]] && break; echo "Povoleno 11-29."; done
     printf -v NODENO "%02d" $((LAST-10)); HOSTNAME_NEW="${SITE}-NODE${NODENO}" ;;
  3) ROLE=MGMT; LAST=9; HOSTNAME_NEW="${SITE}-MGMT" ;;
  *) die "Neplatná role." ;;
esac
TARGET_IP="$BASE.$LAST"
ask WG_HUB_ENDPOINT "MAIN WireGuard endpoint (host/IP:port)" ""
ask WG_HUB_PUBKEY "MAIN WireGuard public key" ""
ask WG_ADDRESS "Management overlay IPv4/CIDR tohoto serveru (např. 10.200.2.11/32)" ""
ask WG_MAIN_IP "Management overlay IPv4 CONTROL/WG HUBu" "10.200.0.1"
ask WG_MANAGER_IP "Management overlay IPv4 DockerStackMoveru" "10.200.0.1"
[[ -n "$WG_HUB_ENDPOINT" && -n "$WG_HUB_PUBKEY" && -n "$WG_ADDRESS" ]] || die "WireGuard údaje jsou povinné."
python3 -c 'import ipaddress,sys; ipaddress.ip_interface(sys.argv[1]); ipaddress.ip_address(sys.argv[2])' "$WG_ADDRESS" "$WG_MAIN_IP" || die "Neplatná management IPv4/CIDR."
echo
echo "Rozhraní: $DEF_IF  Aktuální: $CIDR  Gateway: $GW"
echo "Cíl: $HOSTNAME_NEW  $TARGET_IP/$PREFIX  Role: $ROLE  Site: $SITE"

if [[ "$TARGET_IP" != "$CUR_IP" ]]; then
  if ping -c 2 -W 1 "$TARGET_IP" >/dev/null 2>&1; then die "Cílová IP $TARGET_IP odpovídá na ping."; fi
  if command -v arping >/dev/null && arping -D -I "$DEF_IF" -c 2 "$TARGET_IP" 2>/dev/null | grep -q "Unicast reply"; then die "Cílová IP je používána (ARP)."; fi
fi
read -rp "Pokračovat? [ano/NE]: " YES; [[ "$YES" == ano ]] || exit 0

say "Aktualizace systému"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y upgrade
apt-get install -y ca-certificates curl gnupg jq xfsprogs nftables arping parted wireguard
ok "Systém aktualizován"

say "Docker"
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" >/etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
getent group docker >/dev/null || groupadd docker
id lukas >/dev/null 2>&1 && usermod -aG docker lukas || true
ok "Docker $(docker --version | awk '{print $3}' | tr -d ,)"

say "Hostname"
hostnamectl set-hostname "$HOSTNAME_NEW"
ok "$HOSTNAME_NEW"

if [[ "$ROLE" == NODE ]]; then
  say "DATA disk"
  ROOT_SRC=$(findmnt -no SOURCE /); ROOT_DISK=$(lsblk -s -npo NAME,TYPE "$ROOT_SRC" 2>/dev/null | awk '$2=="disk"{print $1; exit}')
  [[ -n "$ROOT_DISK" ]] || die "Nelze zjistit systémový disk."
  mapfile -t CAND < <(lsblk -dpno NAME,TYPE | awk '$2=="disk"{print $1}' | grep -vx "$ROOT_DISK" || true)
  lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINTS
  ask DATA_DISK "DATA disk" "${CAND[0]:-}"
  [[ -b "$DATA_DISK" ]] || die "Disk $DATA_DISK neexistuje."
  if findmnt "$DATA_DISK" >/dev/null 2>&1 || lsblk -no MOUNTPOINTS "$DATA_DISK" | grep -q /; then die "DATA disk/oddíl je připojen; odmítám formátovat."; fi
  read -rp "VAROVÁNÍ: $DATA_DISK bude SMAZÁN a naformátován XFS. Napiš přesně SMAZAT: " WIPE
  [[ "$WIPE" == SMAZAT ]] || die "Formátování nepotvrzeno."
  wipefs -a "$DATA_DISK"; parted -s "$DATA_DISK" mklabel gpt mkpart primary xfs 0% 100%
  partprobe "$DATA_DISK"; sleep 2
  PART="${DATA_DISK}1"; [[ "$DATA_DISK" =~ nvme ]] && PART="${DATA_DISK}p1"
  mkfs.xfs -f "$PART"; mkdir -p /srv
  UUID=$(blkid -s UUID -o value "$PART"); echo "UUID=$UUID /srv xfs defaults,prjquota 0 2" >>/etc/fstab
  mount /srv; mkdir -p /srv/stacks; chown -R lukas:docker /srv/stacks 2>/dev/null || chown -R root:docker /srv/stacks; chmod 2775 /srv/stacks
  ok "DATA /srv: $(df -h /srv | awk 'NR==2{print $2}')"
fi

say "Portainer Agent"
docker rm -f portainer_agent >/dev/null 2>&1 || true
docker pull portainer/agent:2.45.1
docker run -d --name portainer_agent --restart=always -p 9001:9001 \
 -v /var/run/docker.sock:/var/run/docker.sock \
 -v /var/lib/docker/volumes:/var/lib/docker/volumes \
 -v /:/host portainer/agent:2.45.1 >/dev/null
ok "Portainer Agent :9001"

say "Síťová konfigurace"
NETPLAN=$(find /etc/netplan -maxdepth 1 -type f -name '*.yaml' | head -1)
[[ -n "$NETPLAN" ]] || NETPLAN=/etc/netplan/99-dockerstackmover.yaml
mkdir -p /root/dockerstackmover-backup
[[ -f "$NETPLAN" ]] && cp -a "$NETPLAN" "/root/dockerstackmover-backup/$(basename "$NETPLAN").$(date +%Y%m%d%H%M%S)"
DNS=$(resolvectl dns "$DEF_IF" 2>/dev/null | sed 's/.*: //' | xargs | tr ' ' ',' || true); [[ -n "$DNS" ]] || DNS="1.1.1.1,8.8.8.8"
cat >"$NETPLAN" <<EOF
network:
  version: 2
  ethernets:
    $DEF_IF:
      dhcp4: false
      addresses: [$TARGET_IP/$PREFIX]
      routes:
        - to: default
          via: $GW
      nameservers:
        addresses: [$DNS]
EOF
netplan generate
ok "Netplan validní; konfigurace je připravena."

say "WireGuard management overlay"
install -d -m 700 /etc/wireguard
if [[ ! -f /etc/wireguard/dsm.key ]]; then
  umask 077
  wg genkey | tee /etc/wireguard/dsm.key | wg pubkey > /etc/wireguard/dsm.pub
fi
WG_PRIV=$(cat /etc/wireguard/dsm.key)
WG_PUB=$(cat /etc/wireguard/dsm.pub)
cat >/etc/wireguard/wg-dsm.conf <<EOF
[Interface]
Address = $WG_ADDRESS
PrivateKey = $WG_PRIV

[Peer]
PublicKey = $WG_HUB_PUBKEY
Endpoint = $WG_HUB_ENDPOINT
AllowedIPs = 10.200.0.0/16
PersistentKeepalive = 25
EOF
chmod 600 /etc/wireguard/wg-dsm.conf
systemctl enable wg-quick@wg-dsm
ok "WireGuard připraven; public key: $WG_PUB"

say "Host firewall – management ochrana"
systemctl enable nftables
nft delete table inet dockerstackmover-bootstrap >/dev/null 2>&1 || true
FW_TMP=$(mktemp)
cat >"$FW_TMP" <<EOF
table inet dockerstackmover-bootstrap {
 chain input {
  type filter hook input priority -10; policy accept;
  ct state established,related accept
  iifname "lo" accept
  iifname "wg-dsm" ip saddr $WG_MAIN_IP tcp dport 9001 accept
  iifname "wg-dsm" ip saddr $WG_MANAGER_IP tcp dport 9100 accept
  tcp dport { 9001, 9100 } drop
 }
}
EOF
nft -c -f "$FW_TMP"
nft -f "$FW_TMP"
rm -f "$FW_TMP"
ok "TCP 9001 pouze z $WG_MAIN_IP; TCP 9100 pouze z $WG_MANAGER_IP přes wg-dsm."
echo "Po registraci DockerStackMover převezme management firewall vlastním potvrzovacím/rollback mechanismem."

echo
echo "============================================================"
echo "PŘIPRAVENO: $HOSTNAME_NEW"
echo "LAN/DATA adresa: $TARGET_IP/$PREFIX"
echo "Portainer Agent management: ${WG_ADDRESS%/*}:9001"
echo "WireGuard public key serveru: $WG_PUB"
echo "Na MAIN hub přidej peer s AllowedIPs=$WG_ADDRESS"
echo "Po přidání peeru spusť: sudo systemctl start wg-quick@wg-dsm"
echo "V centrálním Portaineru přidej environment: $HOSTNAME_NEW -> ${WG_ADDRESS%/*}:9001"
echo "DockerStackMover: Site=$SITE, Role=$ROLE, Host IP=$TARGET_IP, Management IP=${WG_ADDRESS%/*}"
echo "Node Agent URL: http://${WG_ADDRESS%/*}:9100"
[[ "$ROLE" == NODE ]] && echo "Poté použij Připravit NODE – nainstaluje Node Agent a nastaví spravovaný firewall."
[[ "$ROLE" == PROXY ]] && echo "Poté použij Připravit server – Node Agent zajistí firewall; Traefik bude spravován jako PROXY."
echo "============================================================"
if [[ "$TARGET_IP" != "$CUR_IP" ]]; then
 echo "IP se změní z $CUR_IP na $TARGET_IP. SSH spojení se přeruší."
 read -rp "Aplikovat Netplan nyní? [ano/NE]: " APPLY
 [[ "$APPLY" == ano ]] && netplan apply || echo "Později spusť: sudo netplan apply"
fi
