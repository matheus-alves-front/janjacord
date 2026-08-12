#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
root_dir="$(cd -- "${script_dir}/.." && pwd -P)"
cd "$root_dir"

command -v docker >/dev/null 2>&1 || {
  echo "release snapshot: Docker is required" >&2
  exit 1
}
[[ -f .env ]] || {
  echo "release snapshot: run ./scripts/init.sh first" >&2
  exit 1
}

label="${1:-$(date -u +%Y%m%dT%H%M%SZ)}"
[[ "$label" =~ ^[A-Za-z0-9._-]+$ ]] || {
  echo "release snapshot: label may contain only letters, numbers, dot, underscore and hyphen" >&2
  exit 2
}

release_dir="${root_dir}/state/releases"
mkdir -p "$release_dir"
chmod 0700 "$release_dir"
snapshot_tmp="$(mktemp "${release_dir}/.${label}.env.tmp.XXXXXX")"
trap 'rm -f "$snapshot_tmp"' EXIT
cp .env "$snapshot_tmp"

replace_image() {
  local service="$1" key="$2" container_id image_id next
  container_id="$(docker compose ps -q "$service")"
  [[ -n "$container_id" ]] || {
    echo "release snapshot: service is not running: ${service}" >&2
    exit 1
  }
  image_id="$(docker inspect --format '{{.Image}}' "$container_id")"
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo "release snapshot: could not resolve immutable image ID for ${service}" >&2
    exit 1
  }
  next="$(mktemp "${release_dir}/.${label}.${service}.tmp.XXXXXX")"
  awk -v key="$key" -v value="$image_id" '
    BEGIN { replaced = 0 }
    index($0, key "=") == 1 { print key "=" value; replaced = 1; next }
    { print }
    END { if (!replaced) print key "=" value }
  ' "$snapshot_tmp" > "$next"
  mv "$next" "$snapshot_tmp"
}

replace_image rendezvous JANJABRIDGE_IMAGE
replace_image gateway NGINX_IMAGE
replace_image coturn COTURN_IMAGE

snapshot="${release_dir}/${label}.env"
mv "$snapshot_tmp" "$snapshot"
chmod 0600 "$snapshot"
sha256sum "$snapshot" > "${snapshot}.sha256"
chmod 0600 "${snapshot}.sha256"
trap - EXIT

echo "release snapshot: ${snapshot}"
echo "release snapshot: restore with --no-build --pull never as documented in README.md"
