from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from verify import verify_vp, parse_jwt_unverified

app = FastAPI()

class VPRequest(BaseModel):
    vp_jwt: str

@app.post("/verify")
def verify(request: VPRequest):
    try:
        result = verify_vp(request.vp_jwt)
        vp = result["claims"]["vp"]
        vc_jwt = vp["verifiableCredential"][0]  # first one only
        _, vc_payload = parse_jwt_unverified(vc_jwt)
        print(vc_payload)

        subject = vc_payload["vc"]["credentialSubject"][0]

        # Example: parse SAN or subject fields from X509Credential
        san = subject.get("san", {}).get("otherName")
        subj = subject.get("subject", {})

        return {
            "status": "valid",
            "holder": result["holder"],
            "user_info": {
                "id": subject.get("id"),
                "subject": subj,
                "san": san,
                "issuer": vc_payload.get("iss")
            }
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))