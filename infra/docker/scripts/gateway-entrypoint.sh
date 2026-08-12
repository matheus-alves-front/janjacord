#!/bin/sh
set -eu

case "${BRIDGE_DOMAIN:-}" in
  ''|*[!A-Za-z0-9.-]*)
    echo "gateway: BRIDGE_DOMAIN is missing or invalid" >&2
    exit 1
    ;;
esac

case "${TURN_DOMAIN:-}" in
  ''|*[!A-Za-z0-9.-]*)
    echo "gateway: TURN_DOMAIN is missing or invalid" >&2
    exit 1
    ;;
esac

case "${TURN_TLS_INTERNAL_PORT:-}" in
  ''|*[!0-9]*)
    echo "gateway: TURN_TLS_INTERNAL_PORT is missing or invalid" >&2
    exit 1
    ;;
esac

if [ "$BRIDGE_DOMAIN" = "$TURN_DOMAIN" ]; then
  echo "gateway: TURN_DOMAIN must differ from BRIDGE_DOMAIN for SNI routing on one IPv4" >&2
  exit 1
fi

live_dir="/etc/letsencrypt/live/${BRIDGE_DOMAIN}"
if [ -r "${live_dir}/fullchain.pem" ] && [ -r "${live_dir}/privkey.pem" ]; then
  TLS_CERT_PATH="${live_dir}/fullchain.pem"
  TLS_KEY_PATH="${live_dir}/privkey.pem"
else
  TLS_CERT_PATH="/bootstrap-tls/fullchain.pem"
  TLS_KEY_PATH="/bootstrap-tls/privkey.pem"
  echo "gateway: ACME certificate not found; using short-lived bootstrap certificate" >&2
fi

export TLS_CERT_PATH TLS_KEY_PATH
envsubst '${BRIDGE_DOMAIN} ${TURN_DOMAIN} ${TURN_TLS_INTERNAL_PORT} ${TLS_CERT_PATH} ${TLS_KEY_PATH}' \
  < /opt/janjabridge/nginx.conf.template \
  > /tmp/nginx.conf

nginx -t -c /tmp/nginx.conf
exec nginx -c /tmp/nginx.conf -g 'daemon off;'
