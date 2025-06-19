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
from urllib.parse import urlparse, parse_qs

app = FastAPI()
init_db()
init_did_table()

templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
async def openid4vp_form(request: Request):
    return templates.TemplateResponse("entry.html", {
        "request": request,
    })

@app.post("/wallet/openid4vp", response_class=HTMLResponse)
async def handle_openid4vp_post(request: Request, raw_uri: str = Form(...)):
    # Parse the `openid4vp://?request_uri=...` URI
    parsed = urlparse(raw_uri)
    if parsed.scheme != "openid4vp":
        return HTMLResponse("Invalid scheme in URI", status_code=400)

    qs = parse_qs(parsed.query)
    request_uri = qs.get("request_uri", [None])[0]
    if not request_uri:
        return HTMLResponse("Missing request_uri in link", status_code=400)

    async with httpx.AsyncClient() as client:
        r = await client.get(request_uri)
        data = r.json()

    creds = list_credentials()
    dids = list_dids()

    return templates.TemplateResponse("select.html", {
        "request": request,
        "request_uri": request_uri,
        "credentials": creds,
        "dids": dids
    })

@app.post("/wallet/respond")
async def handle_response(
    credential_label: str = Form(...),
    holder_label: str = Form(...),
    request_uri: str = Form(...),
):

    # Fetch the presentation request from the verifier
    async with httpx.AsyncClient() as client:
        r = await client.get(request_uri)
        if r.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch request_uri")
        req_data = r.json()

    redirect_uri = req_data.get("redirect_uri")
    if not redirect_uri:
        raise HTTPException(status_code=400, detail="Missing redirect_uri")

    audience = "https://verifier.example.org"
    # audience = req_data.get("client_id") or req_data.get("audience") or redirect_uri
    nonce = req_data.get("nonce")


    # Load user-selected credential and DID
    vc_jwt = get_credential_by_label(credential_label)
    did = get_did_keypair_by_label(holder_label)


    # Create the signed VP
    vp_jwt = create_vp_jwt(
        holder_did=did["did"],
        private_jwk=did["private_jwk"],
        vc_jwt=vc_jwt,
        audience=audience,
        nonce=nonce
    )


    # Send to verifier /openid4vp/callback
    async with httpx.AsyncClient() as client:
        resp = await client.post("http://localhost:8052/openid4vp/callback", json={"vp_jwt": vp_jwt})
        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail=f"Verifier rejected presentation {resp.text}")

        user_info = resp.json().get("user_info")
        if not user_info:
            raise HTTPException(status_code=500, detail="No user_info returned from verifier")

        # Redirect to dummy app with result
        payload = base64.urlsafe_b64encode(json.dumps(user_info).encode()).decode()
        return RedirectResponse(f"{redirect_uri}?data={payload}")

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