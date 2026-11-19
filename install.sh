#!/usr/bin/env bash
# Install YumPi on a Raspberry Pi: Docker, Mullvad, and one container that
# owns the access point, DHCP, and the firewall.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [[ "${EUID}" -ne 0 ]]; then
  exec sudo --preserve-env=YUMPI_ADMIN_PASSWORD,YUMPI_WIFI_PASSPHRASE,YUMPI_SSID,YUMPI_COUNTRY,YUMPI_CHANNEL,YUMPI_WIFI_IF,YUMPI_WIFI_CIDR,YUMPI_WIFI_DHCP_START,YUMPI_WIFI_DHCP_END,YUMPI_LAN_IF,YUMPI_LAN_CIDR,YUMPI_LAN_DHCP_START,YUMPI_LAN_DHCP_END,YUMPI_UPSTREAM \
    "$0" "$@"
fi

log() { printf '==> %s\n' "$*"; }
die() { printf 'yumpi: %s\n' "$*" >&2; exit 1; }

pull_image() {
  local image="$1" i
  for i in 1 2 3 4 5; do
    if docker pull "$image"; then
      return 0
    fi
    log "Registry lookup failed, retrying ${image} (${i}/5)"
    sleep 3
  done
  die "could not pull ${image}"
}

ensure_image() {
  local image="$1"
  if docker image inspect "$image" >/dev/null 2>&1; then
    log "${image} is already on this machine"
    return 0
  fi
  pull_image "$image"
}

# NetworkManager rewrites resolv.conf with the upstream DHCP servers.
# Mullvad rejects those queries, and docker build copies this file in.
pin_mullvad_dns() {
  ip link show wg0-mullvad >/dev/null 2>&1 || return 0
  if [[ -L /etc/resolv.conf ]]; then
    rm -f /etc/resolv.conf
  fi
  printf 'nameserver 10.64.0.1\n' > /etc/resolv.conf
}

gen() {
  local n="$1" i c out=""
  local chars=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
  for ((i = 0; i < n; i++)); do
    c="$(od -An -N1 -tu1 /dev/urandom | tr -d ' ')"
    out+="${chars:$((c % ${#chars})):1}"
  done
  printf '%s' "$out"
}

remove_nft_handles() {
  local chain="$1" pattern="$2" handle
  nft list chain inet mullvad "$chain" >/dev/null 2>&1 || return 0
  while read -r handle; do
    [[ -n "$handle" ]] || continue
    nft delete rule inet mullvad "$chain" handle "$handle" || true
  done < <(nft -a list chain inet mullvad "$chain" | awk -v pat="$pattern" '$0 ~ pat { for (i = 1; i <= NF; i++) if ($i == "handle") print $(i + 1) }')
}

legacy_cleanup() {
  log "Removing the previous YumPi services"
  systemctl disable --now yumpi-web.service yumpi-wlan.service yumpi-net.timer yumpi-net.service 2>/dev/null || true
  systemctl disable --now hostapd.service dnsmasq.service 2>/dev/null || true
  rm -f /etc/systemd/system/yumpi-web.service /etc/systemd/system/yumpi-wlan.service \
    /etc/systemd/system/yumpi-net.service /etc/systemd/system/yumpi-net.timer
  systemctl daemon-reload || true
  rm -rf /opt/yumpi
  rm -f /usr/local/sbin/yumpi-net-sync.sh /etc/dnsmasq.d/yumpi.conf /etc/hostapd/hostapd.conf \
    /etc/yumpi/state.json /etc/yumpi/bypass_ips.txt /etc/hostapd/hostapd.deny
  nft delete table ip yumpi_nat 2>/dev/null || true
  nft delete table inet yumpi_policy 2>/dev/null || true
  nft delete table inet yumpi 2>/dev/null || true
  remove_nft_handles input 'iifname "(wlan0|eth0)".*udp dport 67 accept'
  remove_nft_handles forward 'iifname "wlan0" oifname "wg0-mullvad"'
  remove_nft_handles forward 'iifname "wg0-mullvad" oifname "wlan0"'
  local rule
  for rule in \
    "-i eth0 -o wlan0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" \
    "-i wlan0 -o eth0 -j ACCEPT" \
    "-i wg0-mullvad -o wlan0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" \
    "-i wlan0 -o wg0-mullvad -j ACCEPT" \
    "-i wg0-mullvad -o eth0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" \
    "-i eth0 -o wg0-mullvad -j ACCEPT"
  do
    # shellcheck disable=SC2086
    while iptables -D FORWARD $rule 2>/dev/null; do :; done
  done
  if iptables -S YUMPI >/dev/null 2>&1; then
    while iptables -D FORWARD -j YUMPI 2>/dev/null; do :; done
    iptables -F YUMPI 2>/dev/null || true
    iptables -X YUMPI 2>/dev/null || true
  fi
}

uninstall() {
  log "Stopping YumPi"
  docker compose -f "$ROOT/compose.yml" down || true
  legacy_cleanup
  if [[ "${1:-}" == "--purge" ]]; then
    rm -rf /etc/yumpi /var/lib/yumpi /run/yumpi
    rm -f /etc/tmpfiles.d/yumpi.conf /etc/sysctl.d/99-yumpi.conf \
    /etc/NetworkManager/conf.d/99-yumpi-unmanaged.conf \
    /etc/NetworkManager/conf.d/99-yumpi-dns.conf
  fi
  log "YumPi is stopped. Mullvad and Docker are still installed."
}

if [[ "${1:-}" == "--uninstall" ]]; then
  uninstall "${2:-}"
  exit 0
fi

[[ -f /etc/os-release ]] || die "this installer supports Debian and Raspberry Pi OS"
. /etc/os-release
[[ "${ID:-}" == "debian" || "${ID:-}" == "raspbian" ]] || die "unsupported OS: ${ID:-unknown}"

log "Installing packages"
apt-get update
apt-get install -y ca-certificates curl nftables iptables iproute2 iw rfkill
if ! command -v docker >/dev/null 2>&1; then
  apt-get install -y docker.io
fi
if ! docker compose version >/dev/null 2>&1; then
  apt-get install -y docker-compose-v2 || apt-get install -y docker-compose-plugin || apt-get install -y docker-compose
fi
systemctl enable --now docker

if ! command -v mullvad >/dev/null 2>&1; then
  log "Installing Mullvad"
  curl -fsSLo /usr/share/keyrings/mullvad-keyring.asc https://repository.mullvad.net/deb/mullvad-keyring.asc
  echo "deb [signed-by=/usr/share/keyrings/mullvad-keyring.asc arch=$(dpkg --print-architecture)] https://repository.mullvad.net/deb/stable stable main" > /etc/apt/sources.list.d/mullvad.list
  apt-get update
  apt-get install -y mullvad-vpn
fi
systemctl enable --now mullvad-daemon

log "Turning on forwarding and leaving Wi-Fi to hostapd"
printf 'net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=0\n' > /etc/sysctl.d/99-yumpi.conf
sysctl --system >/dev/null
WIFI_IF="${YUMPI_WIFI_IF:-wlan0}"
COUNTRY="${YUMPI_COUNTRY:-US}"
if command -v raspi-config >/dev/null 2>&1; then
  raspi-config nonint do_wifi_country "$COUNTRY" || true
fi
rfkill unblock wifi || true
if command -v nmcli >/dev/null 2>&1; then
  mkdir -p /etc/NetworkManager/conf.d
  printf '[keyfile]\nunmanaged-devices=interface-name:%s\n' "$WIFI_IF" > /etc/NetworkManager/conf.d/99-yumpi-unmanaged.conf
  printf '[main]\ndns=none\nrc-manager=unmanaged\n' > /etc/NetworkManager/conf.d/99-yumpi-dns.conf
  nmcli dev set "$WIFI_IF" managed no >/dev/null 2>&1 || true
  systemctl reload NetworkManager >/dev/null 2>&1 || true
fi
pin_mullvad_dns

mkdir -p /etc/yumpi /var/lib/yumpi /run/yumpi
chmod 700 /etc/yumpi /var/lib/yumpi
chmod 750 /run/yumpi
printf 'd /etc/yumpi 0700 root root -\nd /var/lib/yumpi 0700 root root -\nd /run/yumpi 0750 root root -\n' > /etc/tmpfiles.d/yumpi.conf

log "Pulling base images"
pin_mullvad_dns
# dockerd remembers the resolver it saw at startup. NetworkManager can
# change that file afterwards, so restart once the Mullvad resolver is in place.
systemctl restart docker
# BuildKit resolves registry DNS in its own namespace, which Mullvad rejects.
# The daemon itself can pull, and the legacy builder then reuses those images.
ensure_image golang:1.27-bookworm
ensure_image debian:trixie-slim
log "Building the container before touching the running network"
# The classic builder reuses local images. BuildKit's own resolver is
# rejected by Mullvad, so keep it off for this build.
DOCKER_BUILDKIT=0 docker build --network=host -t yumpi:local "$ROOT"

if [[ ! -f /etc/yumpi/config.toml ]]; then
  if [[ -z "${YUMPI_LAN_CIDR:-}" || -z "${YUMPI_UPSTREAM:-}" ]]; then
    route="$(ip -4 route show default | head -n1)"
    [[ -n "$route" ]] || die "no default route; set YUMPI_LAN_CIDR and YUMPI_UPSTREAM"
    YUMPI_LAN_IF="${YUMPI_LAN_IF:-$(awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' <<<"$route")}"
    YUMPI_UPSTREAM="${YUMPI_UPSTREAM:-$(awk '{for(i=1;i<=NF;i++) if($i=="via") {print $(i+1); exit}}' <<<"$route")}"
    YUMPI_LAN_CIDR="${YUMPI_LAN_CIDR:-$(ip -4 -o addr show dev "$YUMPI_LAN_IF" | awk '{print $4; exit}')}"
  fi
  if [[ -z "${YUMPI_LAN_DHCP_START:-}" || -z "${YUMPI_LAN_DHCP_END:-}" ]]; then
    [[ "$YUMPI_LAN_CIDR" == */24 ]] || die "set YUMPI_LAN_DHCP_START and YUMPI_LAN_DHCP_END for ${YUMPI_LAN_CIDR}"
    IFS=. read -r a b c d <<<"${YUMPI_LAN_CIDR%%/*}"
    if [[ "$d" -lt 100 ]]; then
      YUMPI_LAN_DHCP_START="${YUMPI_LAN_DHCP_START:-$a.$b.$c.100}"
      YUMPI_LAN_DHCP_END="${YUMPI_LAN_DHCP_END:-$a.$b.$c.200}"
    else
      YUMPI_LAN_DHCP_START="${YUMPI_LAN_DHCP_START:-$a.$b.$c.20}"
      YUMPI_LAN_DHCP_END="${YUMPI_LAN_DHCP_END:-$a.$b.$c.80}"
    fi
  fi
  if [[ -t 0 && -z "${YUMPI_SSID:-}" ]]; then
    read -r -p "Wi-Fi name [YumPi]: " YUMPI_SSID
  fi
  YUMPI_SSID="${YUMPI_SSID:-YumPi}"
  GENERATED_ADMIN=0
  GENERATED_WIFI=0
  if [[ -z "${YUMPI_ADMIN_PASSWORD:-}" ]]; then
    if [[ -t 0 ]]; then
      read -r -s -p "Dashboard password (empty generates one): " YUMPI_ADMIN_PASSWORD
      echo
    fi
  fi
  if [[ -z "${YUMPI_ADMIN_PASSWORD:-}" ]]; then
    YUMPI_ADMIN_PASSWORD="$(gen 20)"
    GENERATED_ADMIN=1
  fi
  if [[ -z "${YUMPI_WIFI_PASSPHRASE:-}" ]]; then
    if [[ -t 0 ]]; then
      read -r -s -p "Wi-Fi password (empty generates one): " YUMPI_WIFI_PASSPHRASE
      echo
    fi
  fi
  if [[ -z "${YUMPI_WIFI_PASSPHRASE:-}" ]]; then
    YUMPI_WIFI_PASSPHRASE="$(gen 16)"
    GENERATED_WIFI=1
  fi
  export YUMPI_ADMIN_PASSWORD YUMPI_WIFI_PASSPHRASE
  model="$(tr -d '\0' </proc/device-tree/model 2>/dev/null || true)"
  docker run --rm \
    -e YUMPI_ADMIN_PASSWORD -e YUMPI_WIFI_PASSPHRASE \
    -v /etc/yumpi:/etc/yumpi \
    --entrypoint /usr/local/bin/yumpi \
    yumpi:local init-config \
      -path /etc/yumpi/config.toml \
      -model "$model" \
      -ssid "$YUMPI_SSID" \
      -country "$COUNTRY" \
      -channel "${YUMPI_CHANNEL:-36}" \
      -wifi-if "$WIFI_IF" \
      -wifi-cidr "${YUMPI_WIFI_CIDR:-10.23.46.1/24}" \
      -wifi-dhcp-start "${YUMPI_WIFI_DHCP_START:-10.23.46.50}" \
      -wifi-dhcp-end "${YUMPI_WIFI_DHCP_END:-10.23.46.200}" \
      -lan-if "${YUMPI_LAN_IF:-eth0}" \
      -lan-cidr "$YUMPI_LAN_CIDR" \
      -lan-dhcp-start "$YUMPI_LAN_DHCP_START" \
      -lan-dhcp-end "$YUMPI_LAN_DHCP_END" \
      -upstream "$YUMPI_UPSTREAM"
else
  GENERATED_ADMIN=0
  GENERATED_WIFI=0
  log "Keeping /etc/yumpi/config.toml"
fi

legacy_cleanup
log "Starting YumPi"
DOCKER_BUILDKIT=0 docker compose -f "$ROOT/compose.yml" up -d --force-recreate --no-build
ok=0
for _ in $(seq 1 40); do
  if curl -kfsS https://127.0.0.1:8443/healthz >/dev/null; then
    ok=1
    break
  fi
  sleep 1
done
[[ "$ok" == 1 ]] || die "the dashboard did not become healthy; docker logs yumpi"

lan_ip="$(awk '
  $0 == "[lan]" { inlan = 1 }
  inlan && $1 == "address" {
    gsub(/"/, "", $3)
    split($3, p, "/")
    print p[1]
    exit
  }
' /etc/yumpi/config.toml)"
printf '\nYumPi is up: https://%s:8443\n' "$lan_ip"
if [[ "$GENERATED_ADMIN" == 1 ]]; then
  printf 'Dashboard password: %s\n' "$YUMPI_ADMIN_PASSWORD"
fi
if [[ "$GENERATED_WIFI" == 1 || -n "${YUMPI_SSID:-}" ]]; then
  printf 'Wi-Fi: %s\n' "${YUMPI_SSID:-see /etc/yumpi/config.toml}"
fi
if [[ "$GENERATED_WIFI" == 1 ]]; then
  printf 'Wi-Fi password: %s\n' "$YUMPI_WIFI_PASSPHRASE"
fi
