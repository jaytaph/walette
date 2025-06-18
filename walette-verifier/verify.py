import datetime

from jwcrypto import jwt, jwk
import json
import base64
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

from pathlib import Path
trusted_root = Path("trusted_root.pem").read_bytes()

def validate_cert_chain(x5c_list, trusted_root_pem):
    if not x5c_list or len(x5c_list) < 1:
        raise ValueError("x5c list must include at least the leaf certificate")

    certs = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in x5c_list]
    leaf = certs[0]

    # Validate cert chain signatures
    for i in range(len(certs) - 1):
        child = certs[i]
        parent = certs[i + 1]
        try:
            parent.public_key().verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15() if isinstance(parent.public_key(), rsa.RSAPublicKey) else None,
                child.signature_hash_algorithm,
            )
        except Exception as e:
            raise ValueError(f"Certificate chain broken at position {i}: {str(e)}")

    # Load trusted root
    root = certs[-1]
    trusted_root = x509.load_pem_x509_certificate(trusted_root_pem)

    if root.fingerprint(hashes.SHA256()) != trusted_root.fingerprint(hashes.SHA256()):
        raise ValueError("Untrusted root certificate")

    # Check leaf validity
    now = datetime.datetime.now(datetime.UTC)
    if now < leaf.not_valid_before_utc or now > leaf.not_valid_after_utc:
        raise ValueError("Leaf certificate is expired or not yet valid")

    return certs

def jwk_from_x5c(x5c_list):
    if not isinstance(x5c_list, list) or not x5c_list:
        raise ValueError("Invalid x5c header")

    cert_der = base64.b64decode(x5c_list[0])
    cert = load_der_x509_certificate(cert_der, backend=default_backend())
    pubkey = cert.public_key()

    # Convert to JWK
    if isinstance(pubkey, rsa.RSAPublicKey):
        numbers = pubkey.public_numbers()
        return {
            "kty": "RSA",
            "n": base64.urlsafe_b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")).decode("utf-8").rstrip("="),
            "e": base64.urlsafe_b64encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")).decode("utf-8").rstrip("=")
        }

    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        raise ValueError("EC keys not implemented yet")

    elif isinstance(pubkey, ed25519.Ed25519PublicKey):
        raw = pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")
        }

    else:
        raise ValueError("Unsupported public key type in x5c")

def verify_jwt_signature(token: str, key_data: dict):
    key = jwk.JWK.from_json(json.dumps(key_data))
    try:
        verified = jwt.JWT(jwt=token, key=key)
        return json.loads(verified.claims)
    except Exception as e:
        raise ValueError(f"Failed to verify JWT signature: {str(e)}")

def check_standard_claims(claims, name="JWT"):
    now = int(time.time())
    if "exp" in claims and now > claims["exp"]:
        raise ValueError(f"{name} expired (exp) {claims['exp']}  {now}")
    if "nbf" in claims and now < claims["nbf"]:
        raise ValueError(f"{name} not valid yet (nbf)")
    if "iat" in claims and now < claims["iat"] - 10:
        raise ValueError(f"{name} issued in the future (iat)")

def parse_jwt_unverified(token):
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    header_b64 = parts[0] + '=='
    payload_b64 = parts[1] + '=='
    header = json.loads(base64.urlsafe_b64decode(header_b64.encode()))
    payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode()))
    return header, payload

def extract_did_jwk(did_jwk_str):
    # Extract base64 from: did:jwk:{base64url(jwk)}
    prefix = "did:jwk:"
    if not did_jwk_str.startswith(prefix):
        raise ValueError("Not a did:jwk")
    b64 = did_jwk_str[len(prefix):]
    padded = b64 + '=' * (4 - len(b64) % 4)
    jwk_json = base64.urlsafe_b64decode(padded.encode()).decode()
    return json.loads(jwk_json)

def validate_vp_structure(vp: dict):
    if not isinstance(vp, dict):
        raise ValueError("VP must be a JSON object")

    ctx = vp.get("@context")
    if not ctx or "https://www.w3.org/2018/credentials/v1" not in ctx:
        raise ValueError("VP missing @context or incorrect context")

    types = vp.get("type", [])
    if isinstance(types, str):
        types = [types]
    if "VerifiablePresentation" not in types:
        raise ValueError("VP type must include 'VerifiablePresentation'")

    creds = vp.get("verifiableCredential")
    if not isinstance(creds, list) or not creds:
        raise ValueError("VP must include at least one verifiableCredential")

def validate_vc_structure(vc_payload: dict):
    vc = vc_payload.get("vc")
    if not vc or not isinstance(vc, dict):
        raise ValueError("VC missing 'vc' claim or not an object")

    ctx = vc.get("@context")
    if not ctx or "https://www.w3.org/2018/credentials/v1" not in ctx:
        raise ValueError("VC missing @context or incorrect context")

    types = vc.get("type", [])
    if isinstance(types, str):
        types = [types]
    if "VerifiableCredential" not in types:
        raise ValueError("VC type must include 'VerifiableCredential'")

    subject = vc.get("credentialSubject")
    if not subject:
        raise ValueError("VC missing credentialSubject")

def verify_vp(token, expected_audience="https://verifier.example.org"):
    header, payload = parse_jwt_unverified(token)

    # --- Check audience
    aud = payload.get("aud")
    if aud != expected_audience:
        raise ValueError(f"Invalid audience: got '{aud}', expected '{expected_audience}'")

    check_standard_claims(payload, name="Verifiable Presentation")

    # --- Extract public key from DID
    did = payload["iss"]
    jwk_pub = extract_did_jwk(did)
    key = jwk.JWK.from_json(json.dumps(jwk_pub))

    # --- Verify signature
    jwt_token = jwt.JWT(jwt=token, key=key)
    claims = json.loads(jwt_token.claims)

    if "vp" not in claims:
        raise ValueError("Missing 'vp' field in presentation")

    vp_data = claims["vp"]
    validate_vp_structure(vp_data)


    vc_list = vp_data.get("verifiableCredential", [])
    for vc_jwt in vc_list:
        if not isinstance(vc_jwt, str):
            raise ValueError("Each verifiableCredential must be a JWT string")
        vc_header, _ = parse_jwt_unverified(vc_jwt)

        if "kid" not in vc_header:
            raise ValueError("VC JWT header missing 'kid'")

        # Support both did:jwk and embedded public key
        if vc_header["kid"].startswith("did:jwk:"):
            issuer_pub = extract_did_jwk(vc_header["kid"])
        elif vc_header["kid"].startswith("did:x509:"):
            x5c = vc_header.get("x5c")
            if not x5c:
                raise ValueError("VC from did:x509 missing x5c")
            validate_cert_chain(x5c, trusted_root)
            issuer_pub = jwk_from_x5c(x5c)

        else:
            raise ValueError("Unsupported kid format in VC JWT")


        # Verify VC signature
        vc_payload = verify_jwt_signature(vc_jwt, issuer_pub)

        check_standard_claims(vc_payload, name="Verifiable Credential")
        validate_vc_structure(vc_payload)

    return {
        "holder": claims["iss"],
        "claims": claims
    }