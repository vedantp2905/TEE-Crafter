#!/bin/sh
# nginx-alb entrypoint.
#
# On first boot, generate a 10-year self-signed cert for the HTTPS
# listener.  The cert lives in a named docker volume (`nginx_certs`),
# so it survives `docker compose restart` and only regenerates if the
# volume is wiped (e.g. `docker compose down -v`).
#
# This is a dev cert — its key is intentionally world-readable so the
# `nginx` worker user can load it without ownership gymnastics.  Never
# reuse this cert outside the sandbox.
set -eu

CERTS_DIR=/certs
mkdir -p "$CERTS_DIR"

if [ ! -f "$CERTS_DIR/cert.pem" ] || [ ! -f "$CERTS_DIR/key.pem" ]; then
    echo "[nginx-alb] generating self-signed dev cert in $CERTS_DIR ..."
    if ! command -v openssl >/dev/null 2>&1; then
        apk add --no-cache openssl >/dev/null 2>&1
    fi
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
        -subj "/CN=tee-crafter-siem-sandbox" \
        -addext "subjectAltName=DNS:localhost,DNS:nginx-alb,IP:127.0.0.1" \
        -keyout "$CERTS_DIR/key.pem" \
        -out    "$CERTS_DIR/cert.pem"
    echo "[nginx-alb] cert generated."
fi
chmod 644 "$CERTS_DIR/cert.pem" "$CERTS_DIR/key.pem"

exec nginx -g 'daemon off;'
