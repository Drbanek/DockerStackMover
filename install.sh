#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "[ERROR] line $LINENO: $BASH_COMMAND" >&2' ERR

[[ ${EUID} -eq 0 ]] || { echo "Run with sudo."; exit 1; }
source /etc/os-release
[[ "${ID:-}" == "ubuntu" ]] || { echo "DockerStackMover bootstrap supports Ubuntu Server."; exit 1; }

export DEBIAN_FRONTEND=noninteractive
IFACE=$(ip -4 route show default | awk 'NR==1{print $5}')
CURRENT_CIDR=$(ip -o -4 addr show dev "$IFACE" scope global | awk 'NR==1{print $4}')
MGMT_IP=${CURRENT_CIDR%/*}
PREFIX=${CURRENT_CIDR#*/}
[[ -n "$MGMT_IP" && -n "$PREFIX" ]] || { echo "Unable to detect management IPv4."; exit 1; }

# DSM address convention: MGMT always uses host address .10 in the detected IPv4 subnet.
IFS=. read -r OCT1 OCT2 OCT3 _ <<<"$MGMT_IP"
TARGET_IP="$OCT1.$OCT2.$OCT3.10"

echo "DockerStackMover · first MGMT bootstrap"
echo "Detected address: $MGMT_IP/$PREFIX"
echo "Target MGMT address: $TARGET_IP/$PREFIX"

if ! command -v docker >/dev/null 2>&1; then
  apt-get update
  apt-get install -y ca-certificates curl
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" >/etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker

# MGMT is always a WireGuard management peer. Prepare its persistent identity
# on the host now; the HUB peer is added later by the first-infrastructure flow.
apt-get update
apt-get install -y wireguard
install -d -m 700 /etc/wireguard
if [[ ! -f /etc/wireguard/dsm-mgmt.key ]]; then
  umask 077
  wg genkey | tee /etc/wireguard/dsm-mgmt.key | wg pubkey >/etc/wireguard/dsm-mgmt.pub
fi
chmod 600 /etc/wireguard/dsm-mgmt.key
chmod 644 /etc/wireguard/dsm-mgmt.pub
MGMT_WG_PUBLIC_KEY=$(cat /etc/wireguard/dsm-mgmt.pub)

# Narrow host helper: only accepts a WireGuard public key and IPv4:port endpoint,
# writes the fixed MGMT address 10.200.0.10/16 and starts wg-dsm.
install -d -m 755 /opt/dockerstackmover-host-tools
cat >/opt/dockerstackmover-host-tools/configure-mgmt-wireguard <<'DSMHELPER'
#!/usr/bin/env bash
set -Eeuo pipefail
HUB_PUB="${1:-}"
ENDPOINT="${2:-}"
[[ "$HUB_PUB" =~ ^[A-Za-z0-9+/]{43}=$ ]] || { echo "Invalid HUB public key" >&2; exit 2; }
[[ "$ENDPOINT" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$ ]] || { echo "Invalid HUB endpoint" >&2; exit 3; }
PRIV=$(cat /etc/wireguard/dsm-mgmt.key)
cat >/etc/wireguard/wg-dsm.conf <<EOF
[Interface]
Address = 10.200.0.10/16
PrivateKey = $PRIV

[Peer]
PublicKey = $HUB_PUB
Endpoint = $ENDPOINT
AllowedIPs = 10.200.0.0/16
PersistentKeepalive = 25
EOF
chmod 600 /etc/wireguard/wg-dsm.conf
systemctl enable wg-quick@wg-dsm >/dev/null
systemctl restart wg-quick@wg-dsm
ip -4 addr show dev wg-dsm | grep -q '10.200.0.10/16'
DSMHELPER
chmod 755 /opt/dockerstackmover-host-tools/configure-mgmt-wireguard

# Narrow privilege bridge for the app container. The container can only submit
# a two-line WireGuard request; this host service validates it and invokes the
# fixed helper. No Docker socket, sudo, or host namespace is exposed.
install -d -m 0755 /opt/dockerstackmover-host-requests
cat >/usr/local/sbin/dockerstackmover-wg-request-handler <<'DSMBROKER'
#!/usr/bin/env bash
set -Eeuo pipefail
REQ=/opt/dockerstackmover-host-requests/request
RES=/opt/dockerstackmover-host-requests/result
[[ -f "$REQ" ]] || exit 0
mapfile -t LINES <"$REQ"
rm -f "$REQ"
if [[ "${#LINES[@]}" -ne 2 ]]; then
  printf 'ERROR invalid request\n' >"$RES"; exit 0
fi
HUB_PUB="${LINES[0]}"
ENDPOINT="${LINES[1]}"
if OUT=$(/opt/dockerstackmover-host-tools/configure-mgmt-wireguard "$HUB_PUB" "$ENDPOINT" 2>&1); then
  printf 'OK\n' >"$RES"
else
  printf 'ERROR %s\n' "${OUT: -300}" >"$RES"
fi
DSMBROKER
chmod 0755 /usr/local/sbin/dockerstackmover-wg-request-handler
cat >/etc/systemd/system/dockerstackmover-wg-request.service <<'EOF'
[Unit]
Description=DockerStackMover MGMT WireGuard request handler
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/dockerstackmover-wg-request-handler
EOF
cat >/etc/systemd/system/dockerstackmover-wg-request.path <<'EOF'
[Unit]
Description=Watch DockerStackMover MGMT WireGuard requests
[Path]
PathExists=/opt/dockerstackmover-host-requests/request
Unit=dockerstackmover-wg-request.service
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now dockerstackmover-wg-request.path

# Prepare the application first on the current address. The permanent IP
# switch is intentionally the final step because an SSH session can be lost.
install -d -m 0750 /opt/dockerstackmover
cat >/opt/dockerstackmover/compose.yaml <<'EOF'
services:
  dockerstackmover:
    image: ghcr.io/drbanek/dockerstackmover:latest
    pull_policy: always
    restart: unless-stopped
    ports:
      - "${MOVER_BIND_IP}:${MOVER_PORT}:8080"
    environment:
      DSM_HOST_IP: "${MOVER_BIND_IP}"
      DSM_HOST_PREFIX: "${MOVER_PREFIX}"
      DSM_WG_PUBLIC_KEY: "${DSM_WG_PUBLIC_KEY}"
    volumes:
      - data:/data
      - /opt/dockerstackmover-host-tools:/host-tools:ro
      - /opt/dockerstackmover-host-requests:/host-requests
volumes:
  data:
EOF
cat >/opt/dockerstackmover/.env <<EOF
MOVER_BIND_IP=$MGMT_IP
MOVER_PREFIX=$PREFIX
MOVER_PORT=8082
DSM_WG_PUBLIC_KEY=$MGMT_WG_PUBLIC_KEY
EOF
chmod 600 /opt/dockerstackmover/.env
cd /opt/dockerstackmover
docker compose pull
docker compose up -d

for _ in $(seq 1 30); do
  if curl -fsS "http://$MGMT_IP:8082/api/setup/status" >/dev/null 2>&1; then
    # Final step: switch MGMT to the DSM-standard .10 address.
    if [[ "$MGMT_IP" != "$TARGET_IP" ]]; then
      if ping -c 1 -W 1 "$TARGET_IP" >/dev/null 2>&1; then
        echo "ERROR: Target MGMT address $TARGET_IP is already in use; IP was not changed." >&2
        exit 1
      fi

      NETPLAN=$(find /etc/netplan -maxdepth 1 -type f \( -name '*.yaml' -o -name '*.yml' \) | head -n1)
      [[ -n "$NETPLAN" ]] || { echo "ERROR: No Netplan configuration found; IP was not changed." >&2; exit 1; }
      GATEWAY=$(ip -4 route show default | awk 'NR==1{print $3}')
      DNS=$(resolvectl dns "$IFACE" 2>/dev/null | awk -F': ' 'NR==1{print $2}' | xargs | tr ' ' ',')
      [[ -n "$DNS" ]] || DNS="$GATEWAY"

      cp -a "$NETPLAN" "$NETPLAN.dsm-backup"
      cat >"$NETPLAN" <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $IFACE:
      dhcp4: false
      addresses:
        - $TARGET_IP/$PREFIX
      routes:
        - to: default
          via: $GATEWAY
      nameservers:
        addresses: [$DNS]
EOF
      chmod 600 "$NETPLAN"

      # Bind DSM to the new address before applying Netplan.
      sed -i "s/^MOVER_BIND_IP=.*/MOVER_BIND_IP=$TARGET_IP/" /opt/dockerstackmover/.env

      echo
      echo "============================================================"
      echo "DockerStackMover is installed."
      echo "MGMT address is now changing: $MGMT_IP -> $TARGET_IP"
      echo "Your SSH session may disconnect now. This is expected."
      echo "Reconnect to: $TARGET_IP"
      echo "Web UI: http://$TARGET_IP:8082"
      echo "============================================================"

      # Apply asynchronously so the final instructions reach the terminal
      # before the old address disappears. Use netplan try first; if the target
      # address does not appear, restore the original DHCP configuration.
      cat >/usr/local/sbin/dockerstackmover-ip-switch <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
NETPLAN='$NETPLAN'
BACKUP='$NETPLAN.dsm-backup'
IFACE='$IFACE'
TARGET_IP='$TARGET_IP'
PREFIX='$PREFIX'
LOG=/var/log/dockerstackmover-ip-switch.log
exec >>"\$LOG" 2>&1

sleep 3
echo "Applying static MGMT address \$TARGET_IP/\$PREFIX on \$IFACE"
if netplan generate; then
  # Ubuntu 26.04 netplan apply regenerates the networkd profile as 0600.
  # Apply first, then make the generated profile group-readable and restart
  # networkd so it can actually match/manage the interface.
  netplan apply || true
  find /run/systemd/network -maxdepth 1 -type f -name '*-netplan-*.network' -exec chmod 0640 {} +
  systemctl restart systemd-networkd
  if true; then
  for _ in \$(seq 1 15); do
    if ip -o -4 addr show dev "\$IFACE" | grep -q " \$TARGET_IP/\$PREFIX "; then
      echo "Target address is active."
      docker compose --env-file /opt/dockerstackmover/.env -f /opt/dockerstackmover/compose.yaml up -d --force-recreate
      exit 0
    fi
    sleep 1
  done
  fi
fi

echo "Static address activation failed; restoring DHCP configuration."
cp -a "\$BACKUP" "\$NETPLAN"
netplan generate
netplan apply || true
find /run/systemd/network -maxdepth 1 -type f -name '*-netplan-*.network' -exec chmod 0640 {} +
systemctl restart systemd-networkd
sed -i "s/^MOVER_BIND_IP=.*/MOVER_BIND_IP=$MGMT_IP/" /opt/dockerstackmover/.env
docker compose --env-file /opt/dockerstackmover/.env -f /opt/dockerstackmover/compose.yaml up -d --force-recreate || true
exit 1
EOF
      chmod 0755 /usr/local/sbin/dockerstackmover-ip-switch
      nohup /usr/local/sbin/dockerstackmover-ip-switch >/dev/null 2>&1 &
      exit 0
    fi

    echo
    echo "============================================================"
    echo "DockerStackMover is ready."
    echo "Open: http://$TARGET_IP:8082"
    echo "All further infrastructure setup continues in the web UI."
    echo "============================================================"
    exit 0
  fi
  sleep 2
done

echo "Container started, but the web health check did not become ready in time." >&2
docker compose ps
exit 1
