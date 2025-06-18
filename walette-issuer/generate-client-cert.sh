#!/usr/bin/env bash

set -e

CN="$1"
if [[ -z "$CN" ]]; then
  echo "Usage: $0 <common-name>"
  exit 1
fi

mkdir -p certs/clients
cd certs

CA_KEY="ca.key.pem"
CA_CERT="ca.cert.pem"

if [[ ! -f "$CA_KEY" || ! -f "$CA_CERT" ]]; then
  echo "Missing CA files: $CA_KEY and/or $CA_CERT"
  exit 1
fi

CLIENT_KEY="clients/${CN}.key.pem"
CLIENT_CSR="clients/${CN}.csr.pem"
CLIENT_CERT="clients/${CN}.cert.pem"

# Generate client private key and CSR
openssl req -newkey rsa:2048 -nodes \
  -keyout "$CLIENT_KEY" \
  -out "$CLIENT_CSR" \
  -subj "/CN=$CN/O=Deadcode Client/L=Netherlands"

# Sign the CSR with the CA
openssl x509 -req -in "$CLIENT_CSR" \
  -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$CLIENT_CERT" -days 365 -sha256

echo "Client certificate generated:"
echo "  - Key : $CLIENT_KEY"
echo "  - Cert: $CLIENT_CERT"