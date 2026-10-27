#!/bin/sh
set -eu

cert_dir="nginx/certs"
key="$cert_dir/nginx.key"
cert="$cert_dir/nginx.crt"

if [ -e "$key" ] || [ -e "$cert" ]; then
    echo "Certificate or private key already exists; refusing to overwrite." >&2
    exit 1
fi

mkdir -p "$cert_dir"
umask 077
openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
    -keyout "$key" -out "$cert" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"
printf 'Created a self-signed localhost certificate at %s\n' "$cert"
