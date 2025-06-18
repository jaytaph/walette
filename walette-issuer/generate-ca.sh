#!/usr/bin/env bash

mkdir -p certs
cd certs

CA_KEY="ca.key.pem"
CA_CERT="ca.cert.pem"

if [[ -f "$CA_KEY" || -f "$CA_CERT" ]]; then
  echo "CA already exists. Skipping generation."
  echo "  $CA_KEY and/or $CA_CERT already present."
  exit 1
fi

# Generate CA certificate and private key
openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
  -keyout "$CA_KEY" \
  -out "$CA_CERT" \
  -subj "/CN=Fake Root CA/O=Deadcode/L=Netherlands" \
  -sha256

echo "CA generated:"
echo "  - $CA_KEY"
echo "  - $CA_CERT"