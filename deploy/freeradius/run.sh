#!/bin/bash
# Starts FreeRADIUS with the certificates in place, and restarts it once a day so a
# renewed server certificate (Caddy renews it every ~60 days) is picked up.
set -euo pipefail

: "${FALLBACK_VLAN:=}"
: "${LDAP_IDENTITY:=}"
: "${LDAP_PASSWORD:=}"
: "${LDAP_REQUIRE_CERT:=demand}"
: "${RESTART_EVERY:=86400}"
export FALLBACK_VLAN LDAP_IDENTITY LDAP_PASSWORD LDAP_REQUIRE_CERT

for v in VSZ_ADDRESS RADIUS_SECRET DEFAULT_DOMAIN LDAP_SERVER LDAP_PORT LDAP_BASE_DN PLATFORM_URL PLATFORM_TOKEN TLS_CERT TLS_KEY LDAP_CLIENT_CERT LDAP_CLIENT_KEY; do
  if [ -z "${!v:-}" ]; then
    echo "run.sh: $v is not set (see radius.env.example)" >&2
    exit 1
  fi
done

# On first boot Caddy may still be getting the certificate: wait for it rather than
# crash-looping. The Google LDAP files are installed by hand, so only warn about those.
waited=0
while [ ! -s "$TLS_CERT" ] || [ ! -s "$TLS_KEY" ]; do
  [ $((waited % 60)) -eq 0 ] && echo "run.sh: waiting for the server certificate at $TLS_CERT (Caddy gets it on first start)" >&2
  sleep 5
  waited=$((waited + 5))
done
for f in "$LDAP_CLIENT_CERT" "$LDAP_CLIENT_KEY"; do
  [ -r "$f" ] || { echo "run.sh: cannot read $f (the Google Secure LDAP client certificate; see the README)" >&2; exit 1; }
done

install_certs() {
  # FreeRADIUS runs as freerad and reads its keys after dropping root, so give it copies.
  install -m 0640 -o root -g freerad "$TLS_CERT" /etc/freeradius/certs/server.pem
  install -m 0640 -o root -g freerad "$TLS_KEY" /etc/freeradius/certs/server.key
  mkdir -p /etc/freeradius/google
  install -m 0640 -o root -g freerad "$LDAP_CLIENT_CERT" /etc/freeradius/google/ldap-client.crt
  install -m 0640 -o root -g freerad "$LDAP_CLIENT_KEY" /etc/freeradius/google/ldap-client.key
}

flags=(-f -l stdout)
[ "${RADIUS_DEBUG:-}" = "1" ] && flags=(-X)

stop() {
  kill -TERM "${pid:-}" "${timer:-}" 2>/dev/null || true
  wait "${pid:-}" 2>/dev/null || true
  exit 0
}
trap stop TERM INT

while true; do
  install_certs
  freeradius -C >/dev/null || { freeradius -XC; exit 1; }
  freeradius "${flags[@]}" &
  pid=$!
  sleep "$RESTART_EVERY" &
  timer=$!
  # Whichever ends first: FreeRADIUS dying is an error (Docker restarts the container),
  # the timer means it's time for the daily restart.
  wait -n "$pid" "$timer" || true
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "run.sh: FreeRADIUS stopped unexpectedly" >&2
    exit 1
  fi
  kill -TERM "$pid"
  wait "$pid" || true
done
