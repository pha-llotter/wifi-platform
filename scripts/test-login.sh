#!/bin/bash
# Logs in to the live FreeRADIUS on this server the way a phone does (EAP-TTLS/PAP with
# eapol_test), with a real school account. Shows whether the login is accepted and the
# VLAN it gets, without needing the vSZ or an access point.
#   sudo ./scripts/test-login.sh t.smith@phahs.org.za
# Reads RADIUS_SECRET and DEFAULT_DOMAIN from /etc/wifi-portal/radius.env. The first run
# builds a small eapol_test image (wifi-portal-eapol).
set -euo pipefail

user="${1:?usage: test-login.sh <email or username>}"
here="$(cd "$(dirname "$0")/.." && pwd)"
envfile="${RADIUS_ENV:-/etc/wifi-portal/radius.env}"
secret="$(grep -E '^RADIUS_SECRET=' "$envfile" | cut -d= -f2-)"
domain="$(grep -E '^DEFAULT_DOMAIN=' "$envfile" | cut -d= -f2-)"
server_name="${SERVER_NAME:-radius.$domain}"
image="${EAPOL_IMAGE:-wifi-portal-eapol}"
radius_host="${RADIUS_HOST:-127.0.0.1}"
network="${DOCKER_NETWORK:-host}"
ca="/etc/ssl/certs/ca-certificates.crt"
[ -n "${CA_CERT:-}" ] && ca="/conf/ca.pem"

read -rsp "Password for $user: " password
echo

if ! docker image inspect "$image" >/dev/null 2>&1; then
  echo "Building the eapol_test image (once)…"
  docker build -q -t "$image" -f "$here/dev/radius-e2e/eapol.Dockerfile" "$here/dev/radius-e2e" >/dev/null
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
chmod 700 "$work"
# The password goes into a file in a folder only this user can open, never on a command line.
esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
cat > "$work/client.conf" <<EOF
network={
  key_mgmt=WPA-EAP
  eap=TTLS
  identity="$(esc "$user")"
  anonymous_identity="anonymous@$domain"
  password="$(esc "$password")"
  phase2="auth=PAP"
  ca_cert="$ca"
  domain_suffix_match="$server_name"
}
EOF
chmod 644 "$work/client.conf" # readable inside the container
[ -n "${CA_CERT:-}" ] && cp "$CA_CERT" "$work/ca.pem" && chmod 644 "$work/ca.pem"

echo "Logging in as $user (expecting the server certificate for $server_name)…"
out="$(docker run --rm --network "$network" --entrypoint eapol_test -v "$work:/conf:ro" "$image" \
  -c /conf/client.conf -a "$radius_host" -p 1812 -s "$secret" -t 20 -M 02:00:00:00:00:99 2>&1 || true)"

if grep -q '^SUCCESS' <<<"$out"; then
  vlan_hex="$(grep -A1 'Tunnel-Private-Group-Id' <<<"$out" | grep -oE 'Value: [0-9a-fA-F]+' | head -1 | cut -d' ' -f2 || true)"
  vlan="$(printf '%s' "${vlan_hex:-}" | sed 's/../\\x&/g')"
  vlan="$(printf "$vlan" | tr -d '\0')"
  echo "✔ Accepted${vlan:+ on VLAN $vlan}."
  echo "  It shows under Activity in the dashboard as device 02:00:00:00:00:99."
else
  echo "✖ Refused, or no answer. The last lines from eapol_test:"
  # Never the hexdumps: the Phase 2 one holds the password.
  lines="$(grep -v -i 'hexdump' <<<"$out" | grep -E '^TLS: |Access-Reject|Reply-Message|CTRL-EVENT-EAP|^FAILURE|No response|timed out' | tail -10 || true)"
  printf '%s\n' "${lines:-$(grep -v -i 'hexdump' <<<"$out" | tail -5)}"
  echo "  Activity in the dashboard shows the reason; RADIUS_DEBUG=1 in radius.env logs more."
  exit 1
fi
