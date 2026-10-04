#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Spusť přes sudo."; exit 1; }

WG_IF=wg-dsm
WG_DIR=/etc/wireguard
WG_CONF=$WG_DIR/$WG_IF.conf
WG_ADDR=${WG_ADDR:-10.200.1.8/16}
WG_PORT=${WG_PORT:-51820}

init_hub() {
  apt-get update
  apt-get install -y wireguard iptables
  cat >/etc/sysctl.d/99-dockerstackmover-wg-forward.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
  sysctl --system >/dev/null
  install -d -m 700 "$WG_DIR"
  if [[ ! -f "$WG_DIR/hub.key" ]]; then
    umask 077
    wg genkey | tee "$WG_DIR/hub.key" | wg pubkey > "$WG_DIR/hub.pub"
  fi
  local priv
  priv=$(cat "$WG_DIR/hub.key")
  if [[ ! -f "$WG_CONF" ]]; then
    cat >"$WG_CONF" <<EOF
[Interface]
Address = $WG_ADDR
ListenPort = $WG_PORT
PrivateKey = $priv
PostUp = iptables -C FORWARD -i $WG_IF -o $WG_IF -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i $WG_IF -o $WG_IF -j ACCEPT
PostDown = iptables -D FORWARD -i $WG_IF -o $WG_IF -j ACCEPT 2>/dev/null || true
EOF
    chmod 600 "$WG_CONF"
  fi
  systemctl enable --now wg-quick@$WG_IF
  # Existing hubs may have been created before PostUp existed; apply forwarding live too.
  iptables -C FORWARD -i "$WG_IF" -o "$WG_IF" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i "$WG_IF" -o "$WG_IF" -j ACCEPT
  echo "Hub public key: $(cat "$WG_DIR/hub.pub")"
  echo "Hub management IP: ${WG_ADDR%/*}"
  echo "UDP port: $WG_PORT"
}

add_peer() {
  [[ -f "$WG_CONF" ]] || { echo "Nejdřív spusť: $0 init"; exit 1; }
  read -rp "Peer name (např. DC2-PROXY): " name
  read -rp "Peer public key: " pub
  read -rp "Peer management IP/CIDR (např. 10.200.2.9/32): " addr
  python3 -c 'import ipaddress,sys; n=ipaddress.ip_network(sys.argv[1], strict=False); assert n.prefixlen==32' "$addr"
  if grep -Fq "$pub" "$WG_CONF"; then echo "Peer už existuje."; exit 1; fi
  cat >>"$WG_CONF" <<EOF

# $name
[Peer]
PublicKey = $pub
AllowedIPs = $addr
EOF
  wg syncconf "$WG_IF" <(wg-quick strip "$WG_IF")
  echo "Peer $name přidán: $addr"
}

case "${1:-}" in
  init) init_hub ;;
  add-peer) add_peer ;;
  show) wg show "$WG_IF" ;;
  *) echo "Použití: sudo $0 {init|add-peer|show}"; exit 1 ;;
esac
