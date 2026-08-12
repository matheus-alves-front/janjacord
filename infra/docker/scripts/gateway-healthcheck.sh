#!/bin/sh
set -eu

turn_port="${TURN_TLS_INTERNAL_PORT:-5349}"

# The rendezvous container performs the protocol-level exact-response probe and coturn
# performs an authenticated allocation. Here we aggregate the gateway config/listeners
# and current dependency reachability without pretending this is an Internet/NAT test.
nginx -t -c /tmp/nginx.conf >/dev/null 2>&1
nc -z -w 2 127.0.0.1 443
nc -z -w 2 127.0.0.1 8443
nc -z -w 2 rendezvous 8920
nc -z -w 2 coturn "$turn_port"
