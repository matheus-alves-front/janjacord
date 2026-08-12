#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
root_dir="$(cd -- "${script_dir}/.." && pwd -P)"
cd "$root_dir"

command -v docker >/dev/null 2>&1 || {
  echo "certificate: Docker is required" >&2
  exit 1
}
[[ -f .env ]] || {
  echo "certificate: run ./scripts/init.sh first" >&2
  exit 1
}

read_env() {
  local key="$1"
  sed -n "s/^${key}=//p" .env | tail -n 1
}

domain="$(read_env BRIDGE_DOMAIN)"
turn_domain="$(read_env TURN_DOMAIN)"
email="$(read_env ACME_EMAIL)"
staging="$(read_env ACME_STAGING)"

[[ "$domain" =~ ^[A-Za-z0-9.-]+$ ]] || {
  echo "certificate: BRIDGE_DOMAIN in .env is invalid" >&2
  exit 1
}
[[ "$turn_domain" =~ ^[A-Za-z0-9.-]+$ && "$turn_domain" != "$domain" ]] || {
  echo "certificate: TURN_DOMAIN in .env must be distinct and valid" >&2
  exit 1
}
[[ "$email" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || {
  echo "certificate: ACME_EMAIL in .env is invalid" >&2
  exit 1
}

docker compose up -d gateway

certbot_args=(
  certonly
  --webroot
  --webroot-path /var/www/certbot
  --domain "$domain"
  --domain "$turn_domain"
  --email "$email"
  --agree-tos
  --no-eff-email
  --keep-until-expiring
  --non-interactive
)
if [[ "$staging" == "true" ]]; then
  certbot_args+=(--test-cert)
fi

docker compose --profile maintenance run --rm certbot "${certbot_args[@]}"
docker compose up -d --force-recreate gateway coturn

echo "certificate: certificate installed; verify https://${domain}/healthz and turns:${turn_domain}:443"
