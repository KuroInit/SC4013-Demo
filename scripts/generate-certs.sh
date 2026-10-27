#!/usr/bin/env sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
CERT_DIR="$ROOT/.certs"
mkdir -p "$CERT_DIR"
if [ -s "$CERT_DIR/lab.crt" ] && [ -s "$CERT_DIR/lab.key" ]; then
  chmod 644 "$CERT_DIR/lab.key"
  printf 'Using existing local lab certificate in %s\n' "$CERT_DIR"
  exit 0
fi
openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 3650 \
  -keyout "$CERT_DIR/lab.key" -out "$CERT_DIR/lab.crt" \
  -subj "/CN=northstar-local-lab" \
  -addext "subjectAltName=DNS:victim,DNS:mock-s3,DNS:localhost,DNS:northstar.localhost,IP:127.0.0.1"
chmod 644 "$CERT_DIR/lab.key"
chmod 644 "$CERT_DIR/lab.crt"
printf 'Created self-signed HTTPS certificate. Browser will require a one-time trust exception.\n'
