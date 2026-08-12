#!/bin/sh
set -eu

secret_file="${TURN_SHARED_SECRET_FILE:-/run/secrets/turn_shared_secret}"
port="${TURN_TLS_PORT:-5349}"

[ -r "$secret_file" ] || exit 1
IFS= read -r turn_secret < "$secret_file"
[ "${#turn_secret}" -ge 32 ] || exit 1

# This is a real authenticated allocation against the local listener. It proves that
# coturn accepted REST credentials; public DNS/NAT/SNI remain an external diagnostic.
username="$(( $(date +%s) + 60 )):docker-health"
timeout 8 turnutils_uclient \
  -Y alloc \
  -I \
  -S \
  -t \
  -p "$port" \
  -n 1 \
  -m 1 \
  -u "$username" \
  -W "$turn_secret" \
  127.0.0.1 >/dev/null 2>&1

unset turn_secret username
