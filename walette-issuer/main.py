import cryptography
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import hashlib
import base64
import os
from jwcrypto import jwt,jwk

app = FastAPI()

VC_CONTEXT = "https://www.w3.org/2018/credentials/v1"
VC_TYPE = ["VerifiableCredential", "X509Credential"]
CA_ISSUER_DID = "did:x509:issuer"

class VCRequest(BaseModel):
    cn: str
    subject_id: str
    san: str = ""
    additional_claims: dict = {}

def extract_subject(cert):
    return {
        attr.oid._name: attr.value
        for attr in cert.subject
    }

def compute_thumbprints(cert: x509.Certificate):
    der = cert.public_bytes(serialization.Encoding.DER)
    x5t = base64.urlsafe_b64encode(hashlib.sha1(der).digest()).decode("ascii").rstrip("=")
    x5t_s256 = base64.urlsafe_b64encode(hashlib.sha256(der).digest()).decode("ascii").rstrip("=")
    return x5t, x5t_s256

def load_cert_chain_pem(pem_path_list):
    """Reads and encodes PEM certs to base64 DER strings for x5c"""
    der_list = []
    for path in pem_path_list:
        with open(path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
            der = cert.public_bytes(serialization.Encoding.DER)
            der_b64 = base64.b64encode(der).decode("ascii")
            der_list.append(der_b64)
    return der_list

def cert_thumbprint(cert: x509.Certificate) -> str:
    der = cert.public_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.DER)
    sha256 = hashlib.sha256(der).digest()
    return base64.urlsafe_b64encode(sha256).decode().rstrip('=')

@app.post("/issue-vc")
def issue_vc(req: VCRequest):
    cert_path = f"certs/clients/{req.cn}.cert.pem"
    key_path = f"certs/clients/{req.cn}.key.pem"

    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        raise HTTPException(status_code=404, detail="Certificate or key not found")

    # Load certificate and private key
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    with open(key_path, "rb") as f:
        key_pem = f.read()
    jwk_key = jwk.JWK.from_pem(key_pem)


    with open(f"certs/clients/{req.cn}.cert.pem", "rb") as f:
        leaf_cert = x509.load_pem_x509_certificate(f.read())

    x5t, x5t_s256 = compute_thumbprints(leaf_cert)

    x5c_chain = load_cert_chain_pem([
        f"certs/clients/{req.cn}.cert.pem",  # client
        "certs/ca.cert.pem"  # root
    ])

    kid = f"did:x509:0:sha256:{cert_thumbprint(cert)}"

    now = datetime.now()
    exp = now + timedelta(days=365)
    nbf = now

    vc = {
        "@context": [VC_CONTEXT],
        "type": VC_TYPE,
        "credentialSubject": [{
            "id": req.subject_id,
            "san": {"otherName": req.san} if req.san else {},
            "subject": extract_subject(cert),
        }],
    }
    vc.update(req.additional_claims)

    claims = {
        "iss": kid,
        "sub": req.subject_id,
        "nbf": int(nbf.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": f"{kid}#{os.urandom(8).hex()}",
        "vc": vc,
    }

    token = jwt.JWT(
        header = {
            "alg": "PS256",
            "kid": kid,
            "typ": "JWT",
            "x5c": x5c_chain,
            "x5t": x5t,
            "x5t#S256": x5t_s256,
        },
        claims=claims
    )
    token.make_signed_token(jwk_key)

    signed_jwt = token.serialize()

    return {
        "vc_jwt": signed_jwt,
        "kid": kid,
        "subject": req.subject_id
    }