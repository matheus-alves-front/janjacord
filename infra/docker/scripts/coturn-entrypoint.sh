#!/bin/sh
set -eu

require_uint() {
  name="$1"
  value="$2"
  case "$value" in
    ''|*[!0-9]*)
      echo "coturn: ${name} must be an unsigned integer" >&2
      exit 1
      ;;
  esac
}

case "${BRIDGE_DOMAIN:-}" in
  ''|*[!A-Za-z0-9.-]*)
    echo "coturn: BRIDGE_DOMAIN is missing or invalid" >&2
    exit 1
    ;;
esac

case "${TURN_DOMAIN:-}" in
  ''|*[!A-Za-z0-9.-]*)
    echo "coturn: TURN_DOMAIN is missing or invalid" >&2
    exit 1
    ;;
esac

case "${TURN_REALM:-}" in
  ''|*[!A-Za-z0-9.-]*)
    echo "coturn: TURN_REALM is missing or invalid" >&2
    exit 1
    ;;
esac

case "${TURN_EXTERNAL_IP:-}" in
  ''|*[!0-9.]*)
    echo "coturn: TURN_EXTERNAL_IP must be a public IPv4 address" >&2
    exit 1
    ;;
esac

TURN_PORT="${TURN_PORT:-3478}"
TURN_TLS_PORT="${TURN_TLS_PORT:-5349}"
TURN_MIN_PORT="${TURN_MIN_PORT:-49160}"
TURN_MAX_PORT="${TURN_MAX_PORT:-49259}"
TURN_USER_QUOTA="${TURN_USER_QUOTA:-4}"
TURN_TOTAL_QUOTA="${TURN_TOTAL_QUOTA:-100}"
TURN_MAX_BPS="${TURN_MAX_BPS:-4000000}"
TURN_BPS_CAPACITY="${TURN_BPS_CAPACITY:-50000000}"

for pair in \
  "TURN_PORT:${TURN_PORT}" \
  "TURN_TLS_PORT:${TURN_TLS_PORT}" \
  "TURN_MIN_PORT:${TURN_MIN_PORT}" \
  "TURN_MAX_PORT:${TURN_MAX_PORT}" \
  "TURN_USER_QUOTA:${TURN_USER_QUOTA}" \
  "TURN_TOTAL_QUOTA:${TURN_TOTAL_QUOTA}" \
  "TURN_MAX_BPS:${TURN_MAX_BPS}" \
  "TURN_BPS_CAPACITY:${TURN_BPS_CAPACITY}"
do
  require_uint "${pair%%:*}" "${pair#*:}"
done

if [ "$TURN_MIN_PORT" -gt "$TURN_MAX_PORT" ]; then
  echo "coturn: TURN_MIN_PORT must not exceed TURN_MAX_PORT" >&2
  exit 1
fi

secret_file="${TURN_SHARED_SECRET_FILE:-/run/secrets/turn_shared_secret}"
if [ ! -r "$secret_file" ]; then
  echo "coturn: TURN shared secret file is not readable" >&2
  exit 1
fi
IFS= read -r turn_secret < "$secret_file"
case "$turn_secret" in
  ''|*[!A-Za-z0-9._~-]*)
    echo "coturn: TURN shared secret has invalid characters" >&2
    exit 1
    ;;
esac
if [ "${#turn_secret}" -lt 32 ]; then
  echo "coturn: TURN shared secret must contain at least 32 characters" >&2
  exit 1
fi

live_dir="/etc/letsencrypt/live/${BRIDGE_DOMAIN}"
if [ -r "${live_dir}/fullchain.pem" ] && [ -r "${live_dir}/privkey.pem" ]; then
  tls_cert="${live_dir}/fullchain.pem"
  tls_key="${live_dir}/privkey.pem"
else
  tls_cert="/bootstrap-tls/fullchain.pem"
  tls_key="/bootstrap-tls/privkey.pem"
  echo "coturn: ACME certificate not found; TURN/TLS is using the bootstrap certificate" >&2
fi

config_file=/run/coturn/turnserver.conf
umask 077
cat > "$config_file" <<EOF
listening-port=${TURN_PORT}
tls-listening-port=${TURN_TLS_PORT}
min-port=${TURN_MIN_PORT}
max-port=${TURN_MAX_PORT}
external-ip=${TURN_EXTERNAL_IP}
realm=${TURN_REALM}
server-name=${TURN_DOMAIN}
fingerprint
use-auth-secret
static-auth-secret=${turn_secret}
stale-nonce=600
user-quota=${TURN_USER_QUOTA}
total-quota=${TURN_TOTAL_QUOTA}
max-bps=${TURN_MAX_BPS}
bps-capacity=${TURN_BPS_CAPACITY}
no-multicast-peers
no-software-attribute
proc-user=nobody
proc-group=nogroup
pidfile=/tmp/turnserver.pid
cert=${tls_cert}
pkey=${tls_key}
simple-log
denied-peer-ip=0.0.0.0-0.255.255.255
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=100.64.0.0-100.127.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.0.0.0-192.0.0.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=198.18.0.0-198.19.255.255
denied-peer-ip=224.0.0.0-255.255.255.255
denied-peer-ip=::-::1
denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
denied-peer-ip=fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff
denied-peer-ip=ff00::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
EOF

unset turn_secret
exec turnserver -c "$config_file" --log-file=stdout
