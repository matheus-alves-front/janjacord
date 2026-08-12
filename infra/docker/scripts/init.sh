#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/init.sh <bridge-domain> <acme-email> <public-ipv4> [turn-domain]
Example: ./scripts/init.sh bridge.example.com ops@example.com 203.0.113.10 turn.bridge.example.com

The TURN hostname defaults to turn.<bridge-domain>. Both names must resolve to the same IPv4.
EOF
  exit 2
}

[[ $# -ge 3 && $# -le 4 ]] || usage

if [[ "$(id -u)" -eq 0 ]]; then
  echo "init: run as the dedicated non-root Docker operator, not root" >&2
  exit 1
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
root_dir="$(cd -- "${script_dir}/.." && pwd -P)"
domain="${1,,}"
email="$2"
public_ip="$3"
turn_domain="${4:-turn.${domain}}"
turn_domain="${turn_domain,,}"

if [[ ! "$domain" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || [[ ${#domain} -gt 253 ]]; then
  echo "init: bridge-domain must be a valid public DNS hostname" >&2
  exit 2
fi

if [[ ! "$turn_domain" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] \
  || [[ ${#turn_domain} -gt 253 ]] || [[ "$turn_domain" == "$domain" ]]; then
  echo "init: turn-domain must be a valid hostname distinct from bridge-domain" >&2
  exit 2
fi

if [[ ! "$email" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; then
  echo "init: acme-email is invalid" >&2
  exit 2
fi

valid_ipv4() {
  local ip="$1" octet
  local -a octets
  IFS=. read -r -a octets <<< "$ip"
  [[ ${#octets[@]} -eq 4 ]] || return 1
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^[0-9]{1,3}$ ]] || return 1
    (( 10#$octet <= 255 )) || return 1
  done
  (( 10#${octets[0]} >= 1 && 10#${octets[0]} <= 223 )) || return 1
  (( 10#${octets[0]} != 10 && 10#${octets[0]} != 127 )) || return 1
  (( !(10#${octets[0]} == 100 && 10#${octets[1]} >= 64 && 10#${octets[1]} <= 127) )) || return 1
  (( !(10#${octets[0]} == 169 && 10#${octets[1]} == 254) )) || return 1
  (( !(10#${octets[0]} == 172 && 10#${octets[1]} >= 16 && 10#${octets[1]} <= 31) )) || return 1
  (( !(10#${octets[0]} == 192 && 10#${octets[1]} == 168) )) || return 1
  (( !(10#${octets[0]} == 198 && (10#${octets[1]} == 18 || 10#${octets[1]} == 19)) )) || return 1
}

if ! valid_ipv4 "$public_ip"; then
  echo "init: public-ipv4 must be a public-facing IPv4 address" >&2
  exit 2
fi

for command_name in node openssl awk sed; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "init: required command not found: ${command_name}" >&2
    exit 1
  }
done

if [[ -e "${root_dir}/.env" \
  || -e "${root_dir}/secrets/turn-shared-secret" \
  || -e "${root_dir}/secrets/bridge-pairing-admin-key" \
  || -e "${root_dir}/secrets/bridge-signing-key.pem" \
  || -e "${root_dir}/state/bridge-descriptor.json" \
  || -e "${root_dir}/state/bridge-pairing.json" ]]; then
  echo "init: deployment is already initialized; refusing to overwrite secrets" >&2
  echo "init: back up secrets/ and state/ before rotating credentials" >&2
  exit 1
fi

mkdir -p \
  "${root_dir}/secrets" \
  "${root_dir}/state/bootstrap-tls" \
  "${root_dir}/state/letsencrypt" \
  "${root_dir}/state/rendezvous" \
  "${root_dir}/state/acme-webroot/.well-known/acme-challenge"

turn_secret="$(openssl rand -hex 32)"
pairing_admin_key="$(openssl rand -base64 48 | tr -d '\n=' | tr '+/' '-_')"
env_tmp="$(mktemp "${root_dir}/.env.tmp.XXXXXX")"
turn_tmp="$(mktemp "${root_dir}/secrets/turn-shared-secret.tmp.XXXXXX")"
pairing_tmp="$(mktemp "${root_dir}/secrets/bridge-pairing-admin-key.tmp.XXXXXX")"
descriptor_tmp="$(mktemp "${root_dir}/state/bridge-descriptor.json.tmp.XXXXXX")"
pairing_json_tmp="$(mktemp "${root_dir}/state/bridge-pairing.json.tmp.XXXXXX")"
signing_key_tmp="$(mktemp "${root_dir}/secrets/bridge-signing-key.pem.tmp.XXXXXX")"
cert_tmp="$(mktemp "${root_dir}/state/bootstrap-tls/fullchain.pem.tmp.XXXXXX")"
key_tmp="$(mktemp "${root_dir}/state/bootstrap-tls/privkey.pem.tmp.XXXXXX")"

cleanup() {
  rm -f "$env_tmp" "$turn_tmp" "$pairing_tmp" "$descriptor_tmp" "$pairing_json_tmp" "$signing_key_tmp" "$cert_tmp" "$key_tmp"
}
trap cleanup EXIT

cat > "$env_tmp" <<EOF
COMPOSE_PROJECT_NAME=janjabridge
JANJABRIDGE_UID=$(id -u)
JANJABRIDGE_GID=$(id -g)
BRIDGE_DOMAIN=${domain}
TURN_DOMAIN=${turn_domain}
ACME_EMAIL=${email}
ACME_STAGING=false
TURN_EXTERNAL_IP=${public_ip}
TURN_REALM=${domain}
TURN_PORT=3478
TURN_TLS_PORT=443
TURN_TLS_INTERNAL_PORT=5349
TURN_MIN_PORT=49160
TURN_MAX_PORT=49259
TURN_USER_QUOTA=4
TURN_TOTAL_QUOTA=100
TURN_MAX_BPS=4000000
TURN_BPS_CAPACITY=50000000
JC_RENDEZVOUS_MAX_TTL_MS=300000
JC_RENDEZVOUS_RATE_LIMIT=120
JANJABRIDGE_IMAGE=janjacord/rendezvous:local
NODE_IMAGE=node:24.17.0-alpine3.23@sha256:7c70d1235c0b4c2bc9eeed5393d19f1bbdde6885ba0d58ba62bb385d7b0f3ff1
NGINX_IMAGE=nginx:1.28.3-alpine@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236
COTURN_IMAGE=coturn/coturn:4.15.0-r0@sha256:0feee4fc1f45c7c053c8fee3e1ab941b1a1b9a0429bc01e18126735410770bfd
CERTBOT_IMAGE=certbot/certbot:v5.7.0@sha256:34ee91d2f43008eb78a007d22f23ed4b2eaa9a454cb27ca2c042b49527a695b4
RENDEZVOUS_MEMORY=256m
RENDEZVOUS_CPUS=1.0
GATEWAY_MEMORY=128m
GATEWAY_CPUS=0.5
COTURN_MEMORY=512m
COTURN_CPUS=2.0
EOF

printf '%s\n' "$turn_secret" > "$turn_tmp"
printf '%s\n' "$pairing_admin_key" > "$pairing_tmp"

node "${script_dir}/generate-descriptor.mjs" \
  "$domain" "$turn_domain" "443" "$descriptor_tmp" "$signing_key_tmp"
node "${script_dir}/mint-pairing-token.mjs" \
  "$descriptor_tmp" "$pairing_tmp" "$pairing_json_tmp" 24

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 7 \
  -subj "/CN=${domain}" \
  -addext "subjectAltName=DNS:${domain},DNS:${turn_domain}" \
  -keyout "$key_tmp" \
  -out "$cert_tmp" >/dev/null 2>&1

if grep -Fq "$turn_secret" "$descriptor_tmp" "$pairing_json_tmp"; then
  echo "init: refusing to write a descriptor containing the TURN shared secret" >&2
  exit 1
fi

chmod 0600 "$env_tmp" "$turn_tmp" "$pairing_tmp" "$pairing_json_tmp" "$signing_key_tmp" "$key_tmp"
chmod 0644 "$descriptor_tmp" "$cert_tmp"
mv "$env_tmp" "${root_dir}/.env"
mv "$turn_tmp" "${root_dir}/secrets/turn-shared-secret"
mv "$pairing_tmp" "${root_dir}/secrets/bridge-pairing-admin-key"
mv "$signing_key_tmp" "${root_dir}/secrets/bridge-signing-key.pem"
mv "$descriptor_tmp" "${root_dir}/state/bridge-descriptor.json"
mv "$pairing_json_tmp" "${root_dir}/state/bridge-pairing.json"
mv "$cert_tmp" "${root_dir}/state/bootstrap-tls/fullchain.pem"
mv "$key_tmp" "${root_dir}/state/bootstrap-tls/privkey.pem"

trap - EXIT
unset turn_secret pairing_admin_key

cat <<EOF
JanjaBridge initialized for ${domain}.

Generated:
  .env
  secrets/turn-shared-secret
  secrets/bridge-pairing-admin-key
  secrets/bridge-signing-key.pem
  state/bridge-descriptor.json
  state/bridge-pairing.json
  state/bootstrap-tls/{fullchain,privkey}.pem

Next:
  1. Confirm DNS A for ${domain} and ${turn_domain} points to ${public_ip}.
  2. Open the firewall ports documented in README.md.
  3. Run: docker compose config --quiet
  4. Run: docker compose up -d --build
  5. Run: ./scripts/issue-certificate.sh
  6. Share state/bridge-pairing.json once. Mint replacements with ./scripts/mint-pairing.sh.
EOF
