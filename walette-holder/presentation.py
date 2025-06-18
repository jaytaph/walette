import uuid
import time
import json
from jwcrypto import jwk, jwt


def create_vp_jwt(holder_did, private_jwk, vc_jwt, audience=None, nonce=None):
    key = jwk.JWK.from_json(json.dumps(private_jwk))
    now = int(time.time())

    claims = {
        "iss": holder_did,
        "sub": holder_did,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + 600,
        "vp": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": [vc_jwt]
        }
    }

    if audience:
        claims["aud"] = audience
    if nonce:
        claims["nonce"] = nonce

    token = jwt.JWT(header={"alg": "EdDSA"}, claims=claims)
    token.make_signed_token(key)
    return token.serialize()