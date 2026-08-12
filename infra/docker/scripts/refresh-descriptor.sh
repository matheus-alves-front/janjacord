#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
root_dir="$(cd -- "${script_dir}/.." && pwd -P)"

if [[ "$(id -u)" -eq 0 ]]; then
  echo "descriptor: run as the dedicated non-root Docker operator, not root" >&2
  exit 1
fi

for required in \
  "${root_dir}/.env" \
  "${root_dir}/secrets/bridge-signing-key.pem" \
  "${root_dir}/secrets/turn-shared-secret"
do
  [[ -r "$required" ]] || {
    echo "descriptor: required file is not readable: ${required}" >&2
    exit 1
  }
done

read_env() {
  local key="$1"
  sed -n "s/^${key}=//p" "${root_dir}/.env" | tail -n 1
}

domain="$(read_env BRIDGE_DOMAIN)"
turn_domain="$(read_env TURN_DOMAIN)"
turn_tls_port="$(read_env TURN_TLS_PORT)"
expected_uid="$(read_env JANJABRIDGE_UID)"
expected_gid="$(read_env JANJABRIDGE_GID)"
if [[ "$expected_uid" != "$(id -u)" || "$expected_gid" != "$(id -g)" ]]; then
  echo "descriptor: run with the UID/GID recorded by init.sh (${expected_uid}:${expected_gid})" >&2
  exit 1
fi
if [[ ! "$domain" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]]; then
  echo "descriptor: BRIDGE_DOMAIN in .env is invalid" >&2
  exit 1
fi
if [[ ! "$turn_domain" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] \
  || [[ "$turn_domain" == "$domain" ]]; then
  echo "descriptor: TURN_DOMAIN in .env must be a distinct valid hostname" >&2
  exit 1
fi
if [[ ! "$turn_tls_port" =~ ^[0-9]+$ ]] || (( turn_tls_port < 1 || turn_tls_port > 65535 )); then
  echo "descriptor: TURN_TLS_PORT in .env is invalid" >&2
  exit 1
fi

IFS= read -r turn_secret < "${root_dir}/secrets/turn-shared-secret"
descriptor_tmp="$(mktemp "${root_dir}/state/bridge-descriptor.json.tmp.XXXXXX")"
key_tmp="$(mktemp "${root_dir}/secrets/bridge-signing-key.pem.tmp.XXXXXX")"

cleanup() {
  rm -f "$descriptor_tmp" "$key_tmp"
}
trap cleanup EXIT

node "${script_dir}/generate-descriptor.mjs" \
  "$domain" "$turn_domain" "$turn_tls_port" "$descriptor_tmp" "$key_tmp" \
  "${root_dir}/secrets/bridge-signing-key.pem"

if grep -Fq "$turn_secret" "$descriptor_tmp"; then
  echo "descriptor: refusing to write JSON containing the TURN shared secret" >&2
  exit 1
fi

chmod 0644 "$descriptor_tmp"
chmod 0600 "$key_tmp"
mv "$descriptor_tmp" "${root_dir}/state/bridge-descriptor.json"
mv "$key_tmp" "${root_dir}/secrets/bridge-signing-key.pem"
trap - EXIT
unset turn_secret

expires_at="$(node -e 'const d=require(process.argv[1]); console.log(new Date(d.payload.expiresAt).toISOString())' "${root_dir}/state/bridge-descriptor.json")"
echo "descriptor: refreshed with the existing signing key; expires at ${expires_at}"
echo "descriptor: redistribute state/bridge-descriptor.json to bridge owners"
echo "descriptor: existing one-shot pairing documents are not renewed; run ./scripts/mint-pairing.sh when needed"
