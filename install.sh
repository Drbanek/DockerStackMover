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

# DSM 2.1 address convention: CONTROL/MGMT always uses host address .9.
IFS=. read -r OCT1 OCT2 OCT3 _ <<<"$MGMT_IP"
TARGET_IP="$OCT1.$OCT2.$OCT3.9"

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

# CONTROL/MGMT is the central WireGuard HUB. It is not a Site 1 peer.
apt-get update
apt-get install -y wireguard
install -d -m 700 /etc/wireguard
if [[ ! -f /etc/wireguard/hub.key ]]; then
  umask 077
  wg genkey | tee /etc/wireguard/hub.key | wg pubkey >/etc/wireguard/hub.pub
fi
chmod 600 /etc/wireguard/hub.key
chmod 644 /etc/wireguard/hub.pub
HUB_WG_PUBLIC_KEY=$(cat /etc/wireguard/hub.pub)
HUB_WG_PRIVATE_KEY=$(cat /etc/wireguard/hub.key)
cat >/etc/wireguard/wg-dsm.conf <<EOF
[Interface]
Address = 10.200.0.1/16
ListenPort = 51820
PrivateKey = $HUB_WG_PRIVATE_KEY
PostUp = iptables -C FORWARD -i wg-dsm -o wg-dsm -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i wg-dsm -o wg-dsm -j ACCEPT
PostDown = iptables -D FORWARD -i wg-dsm -o wg-dsm -j ACCEPT 2>/dev/null || true
EOF
chmod 600 /etc/wireguard/wg-dsm.conf
printf 'net.ipv4.ip_forward=1\n' >/etc/sysctl.d/99-dockerstackmover-wg-forward.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null
systemctl enable --now wg-quick@wg-dsm

# Narrow self-update helper. The web app can only request a fixed update of
# /opt/dockerstackmover using the published GHCR :latest image.
install -d -m 0755 /opt/dockerstackmover-host-tools /opt/dockerstackmover-host-requests
cat >/opt/dockerstackmover-host-tools/update-dsm <<'DSMUPDATE'
#!/usr/bin/env bash
set -Eeuo pipefail
cd /opt/dockerstackmover
docker compose pull dockerstackmover
docker compose up -d --no-deps dockerstackmover
DSMUPDATE
chmod 0755 /opt/dockerstackmover-host-tools/update-dsm

cat >/usr/local/sbin/dockerstackmover-update-request-handler <<'DSMUPDATEBROKER'
#!/usr/bin/env bash
set -Eeuo pipefail
REQ=/opt/dockerstackmover-host-requests/update-request
RES=/opt/dockerstackmover-host-requests/update-result
[[ -f "$REQ" ]] || exit 0
VALUE=$(tr -d '\r\n' <"$REQ")
rm -f "$REQ"
if [[ "$VALUE" != "UPDATE" ]]; then
  printf 'ERROR invalid update request\n' >"$RES"
  exit 0
fi
printf 'RUNNING\n' >"$RES"
if OUT=$(/opt/dockerstackmover-host-tools/update-dsm 2>&1); then
  printf 'OK %s\n' "$(date -u +%FT%TZ)" >"$RES"
else
  RC=$?
  printf 'ERROR rc=%s %s\n' "$RC" "$(printf '%s' "$OUT" | tail -c 500)" >"$RES"
fi
DSMUPDATEBROKER
chmod 0755 /usr/local/sbin/dockerstackmover-update-request-handler

cat >/etc/systemd/system/dockerstackmover-update-request.service <<'EOF'
[Unit]
Description=DockerStackMover self-update request handler
After=docker.service
Requires=docker.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/dockerstackmover-update-request-handler
EOF
cat >/etc/systemd/system/dockerstackmover-update-request.path <<'EOF'
[Unit]
Description=Watch DockerStackMover self-update requests
[Path]
PathExists=/opt/dockerstackmover-host-requests/update-request
Unit=dockerstackmover-update-request.service
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now dockerstackmover-update-request.path

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
DSM_WG_PUBLIC_KEY=$HUB_WG_PUBLIC_KEY
EOF
chmod 600 /opt/dockerstackmover/.env
cd /opt/dockerstackmover
docker compose pull
docker compose up -d

for _ in $(seq 1 30); do
  if curl -fsS "http://$MGMT_IP:8082/api/setup/status" >/dev/null 2>&1; then
    # Final step: switch CONTROL/MGMT to the DSM-standard .9 address.
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
