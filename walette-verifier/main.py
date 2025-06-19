from typing import Dict
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Path
from pydantic import BaseModel, AnyHttpUrl
from starlette.requests import Request

from verify import verify_vp, parse_jwt_unverified

app = FastAPI()

presentation_requests: Dict[str, dict] = {}

class InitiateRequest(BaseModel):
    presentation_definition: dict
    redirect_uri: AnyHttpUrl

class InitiateResponse(BaseModel):
    request_uri: str

@app.post("/openid4vp/initiate", response_model=InitiateResponse)
def initiate_vp(request: Request, req: InitiateRequest):
    request_id = str(uuid4())

    # Store the request (in memory; production should use Redis or DB)
    presentation_requests[request_id] = {
        "presentation_definition": req.presentation_definition,
        "redirect_uri": req.redirect_uri
    }

    return {
        "request_uri": f"{request.url.scheme}://{request.url.hostname}:{request.url.port}/openid4vp/request/{request_id}"
    }

@app.get("/openid4vp/request/{request_id}")
def get_presentation_request(request_id: str = Path(...)):
    if request_id not in presentation_requests:
        raise HTTPException(status_code=404, detail="Request not found")

    return presentation_requests[request_id]


class VPRequest(BaseModel):
    vp_jwt: str

@app.post("/openid4vp/callback")
def openid4vp_callback(request: VPRequest):
    try:
        result = verify_vp(request.vp_jwt)
        vp = result["claims"]["vp"]
        vc_jwt = vp["verifiableCredential"][0]  # first one only
        _, vc_payload = parse_jwt_unverified(vc_jwt)

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