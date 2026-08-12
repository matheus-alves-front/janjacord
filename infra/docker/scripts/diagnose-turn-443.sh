#!/usr/bin/env bash
set -Eeuo pipefail

command -v docker >/dev/null 2>&1 || {
  echo "TURN diagnostic: Docker is required" >&2
  exit 1
}
command -v node >/dev/null 2>&1 || {
  echo "TURN diagnostic: Node.js is required to read the credential packet" >&2
  exit 1
}
[[ $# -eq 1 && -r "$1" ]] || {
  echo "Usage: ./scripts/diagnose-turn-443.sh <temporary-credential.json>" >&2
  exit 2
}

credential_file="$(realpath -- "$1")"
[[ "$(stat -c '%a' "$credential_file")" == "600" ]] || {
  echo "TURN diagnostic: credential packet must have mode 0600" >&2
  exit 1
}
read_field() {
  node -e '
    const packet = require(process.argv[1]);
    const value = packet[process.argv[2]];
    if (typeof value !== "string" && typeof value !== "number") process.exit(1);
    process.stdout.write(String(value));
  ' "$credential_file" "$1"
}

turn_domain="$(read_field turnDomain)"
turn_port="$(read_field turnTlsPort)"
username="$(read_field username)"
credential="$(read_field credential)"
expires_at="$(read_field expiresAt)"
coturn_image="$(read_field coturnImage)"

[[ "$turn_domain" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || {
  echo "TURN diagnostic: TURN_DOMAIN is invalid" >&2
  exit 1
}
[[ "$turn_port" =~ ^[0-9]+$ ]] && (( turn_port >= 1 && turn_port <= 65535 )) || {
  echo "TURN diagnostic: TURN_TLS_PORT is invalid" >&2
  exit 1
}
[[ "$coturn_image" == *@sha256:* ]] || {
  echo "TURN diagnostic: COTURN_IMAGE must be pinned by digest" >&2
  exit 1
}
[[ "$username" =~ ^[0-9]+:external-[0-9a-f]{24}$ ]] || {
  echo "TURN diagnostic: temporary username is invalid" >&2
  exit 1
}
[[ "$credential" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || {
  echo "TURN diagnostic: temporary credential is invalid" >&2
  exit 1
}
[[ "$expires_at" =~ ^[0-9]+$ ]] && (( expires_at > $(date +%s) * 1000 )) || {
  echo "TURN diagnostic: temporary credential is expired" >&2
  exit 1
}

echo "TURN diagnostic: testing authenticated TURN/TLS allocation at ${turn_domain}:${turn_port}"
echo "TURN diagnostic: run this from the client network being qualified; bridge-host hairpin NAT is not acceptance"

docker run --rm \
  --user 0:0 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --entrypoint /bin/sh \
  "$coturn_image" \
  -eu -c '
    timeout 15 turnutils_uclient \
      -Y alloc -I -S -t -p "$2" -n 1 -m 1 \
      -E /etc/ssl/certs/ca-certificates.crt \
      -u "$3" -w "$4" "$1" >/dev/null 2>&1
  ' sh "$turn_domain" "$turn_port" "$username" "$credential"

unset username credential
echo "TURN diagnostic: authenticated allocation over TLS/TCP 443 succeeded"
