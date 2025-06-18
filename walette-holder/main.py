import base64
import json

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi import Form

from starlette.responses import RedirectResponse, HTMLResponse
from starlette.templating import Jinja2Templates

from dids import generate_jwk_did
from models import CreateDIDRequest, AddCredentialRequest
from presentation import create_vp_jwt
from storage import init_db, list_credentials, init_did_table, list_dids, \
    store_did, store_credential_with_label, get_credential_by_label, get_did_keypair_by_label

app = FastAPI()
init_db()
init_did_table()

@app.post("/credentials")
def add_credential(req: AddCredentialRequest):
    try:
        cred_id = store_credential_with_label(req.label, req.jwt)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to store: {str(e)}")
    return {"status": "stored", "id": cred_id}

@app.get("/credentials")
def get_credentials():
    return list_credentials()

templates = Jinja2Templates(directory="templates")

@app.get("/present", response_class=HTMLResponse)
def select_credential(request: Request):
    offer_uri = request.query_params.get("credential_offer_uri")
    state = request.query_params.get("state")

    creds = list_credentials()  # returns [{"label": ..., "jwt": ...}]
    dids = list_dids()          # returns [{"label": ..., "did": ..., "public_jwk": ...}]

    return templates.TemplateResponse("select.html", {
        "request": request,
        "credential_offer_uri": offer_uri,
        "state": state,
        "credentials": creds,
        "dids": dids
    })

@app.post("/present")
async def handle_presentation(
    credential_label: str = Form(...),
    holder_label: str = Form(...),
    credential_offer_uri: str = Form(...),
    state: str = Form(...)
):
    # Parse offer URI
    offer_json = base64.urlsafe_b64decode(credential_offer_uri + '===').decode()
    offer = json.loads(offer_json)

    audience = offer.get("client_id") or offer.get("credential_issuer")
    nonce = offer.get("nonce")

    vc_jwt = get_credential_by_label(credential_label)
    did = get_did_keypair_by_label(holder_label)

    vp_jwt = create_vp_jwt(
        holder_did=did["did"],
        private_jwk=did["private_jwk"],
        vc_jwt=vc_jwt,
        audience=audience,
        nonce=nonce
    )

    async with httpx.AsyncClient() as client:
        resp = await client.post("http://verifier:8000/verify", json={"vp_jwt": vp_jwt})
        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail=f"Verifier rejected presentation {resp.text}")

        user_info = resp.json().get("user_info")
        if not user_info:
            raise HTTPException(status_code=500, detail="No user_info returned from verifier")

        # Pass user_info to dummy app (serialize as base64 JSON)
        payload = base64.urlsafe_b64encode(json.dumps(user_info).encode()).decode()
        return RedirectResponse(f"http://localhost:8053/callback?data={payload}")

@app.post("/dids")
def create_did(req: CreateDIDRequest):
    result = generate_jwk_did()
    try:
        store_did(req.label, result["did"], result["public_jwk"], result["private_jwk"])
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to store DID: {str(e)}")
    return {
        "label": req.label,
        "did": result["did"],
        "public_jwk": result["public_jwk"],
        "private_jwk": result["private_jwk"]
    }


@app.get("/dids")
def get_dids():
    return list_dids()