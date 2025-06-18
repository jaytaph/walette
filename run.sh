#!/usr/bin/env bash

# Generate the CA and client certificates
cd walette-issuer
./generate-ca.sh
./generate-client-cert.sh test-cert-1
./generate-client-cert.sh test-cert-2
./generate-client-cert.sh test-cert-3
cd ..

# Start the containers
docker compose up -d


echo -e "\033[1;33mGenerating a X509 VC from the issuer...\033[0m"
# Curl the issuer to fetch the VC
VC=`curl -X POST http://localhost:8050/issue-vc \
  -H "Content-Type: application/json" \
  -d '{
    "cn": "test-cert-1",
    "subject_id": "did:jwk:abc123",
    "san": "2.16.528.1.1007.99.2110-1-11111111-S-22222222-00.000-33333333"
}' | jq .vc_jwt -r`


echo -e "\033[1;33mStoring the X509 VC into the holder/wallet...\033[0m"
jq -n --arg jwt "$VC" --arg label "test-cert-1 credential" \
  '{label: $label, jwt: $jwt}' > test-cert-1-issue.json

curl -X POST http://localhost:8051/credentials \
  -H "Content-Type: application/json" \
  -d @test-cert-1-issue.json

echo -e "\033[1;33mCreating a new DID for the holder/wallet...\033[0m"
curl -X POST http://localhost:8051/dids -H "Content-Type: application/json" -d '{"label": "test-did"}'

echo
echo
echo

echo -e "\033[1;33mAll done\033[0m"
echo

cat <<EOF
--------------------------------------------------------------------
  You should be able to see the credential and dids in the holder

  http://localhost:8051/dids
  http://localhost:8051/credentials

--------------------------------------------------------------------
EOF
