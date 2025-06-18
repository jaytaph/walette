from jwcrypto import jwk
import base64
import json

def generate_jwk_did():
    key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
    pub = key.export(private_key=False, as_dict=True)

    # Base64URL-encode the public JWK
    pub_str = json.dumps(pub, separators=(",", ":")).encode("utf-8")
    pub_b64url = base64.urlsafe_b64encode(pub_str).decode("utf-8").rstrip("=")

    did = f"did:jwk:{pub_b64url}"
    return {
        "did": did,
        "private_jwk": key.export(private_key=True),
        "public_jwk": key.export(private_key=False)
    }