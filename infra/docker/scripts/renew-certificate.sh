#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
root_dir="$(cd -- "${script_dir}/.." && pwd -P)"
cd "$root_dir"

command -v docker >/dev/null 2>&1 || {
  echo "renew: Docker is required" >&2
  exit 1
}
[[ -f .env ]] || {
  echo "renew: run ./scripts/init.sh first" >&2
  exit 1
}

docker compose --profile maintenance run --rm certbot \
  renew --webroot --webroot-path /var/www/certbot --quiet
docker compose up -d --force-recreate gateway coturn

echo "renew: renewal check complete; gateway and coturn reloaded their certificate"
