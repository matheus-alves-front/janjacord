#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
root_dir="$(cd -- "${script_dir}/.." && pwd -P)"
ttl_hours="${1:-24}"
[[ "$ttl_hours" =~ ^[0-9]+$ ]] || { echo "mint-pairing: TTL hours must be an integer" >&2; exit 2; }
output="${root_dir}/state/bridge-pairing-$(date -u +%Y%m%dT%H%M%SZ).json"
node "${script_dir}/mint-pairing-token.mjs" \
  "${root_dir}/state/bridge-descriptor.json" \
  "${root_dir}/secrets/bridge-pairing-admin-key" \
  "$output" "$ttl_hours"
chmod 0600 "$output"
echo "mint-pairing: share once via a trusted channel: ${output}"
