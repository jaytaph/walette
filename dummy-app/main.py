from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from uuid import uuid4
import base64
import json

app = FastAPI()
templates = Jinja2Templates(directory="templates")

sessions = {}  # session store: session_id → user_info

@app.get("/", response_class=HTMLResponse)
def login_screen(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/login")
def start_login():
    state = str(uuid4())
    credential_offer = {
        "credential_issuer": "http://verifier:8000",
        "client_id": "https://verifier.example.org",
        "nonce": state,
        "presentation_definition": {
            "input_descriptors": [{
                "id": "x509-login",
                "format": "jwt_vc",
                "constraints": {
                    "fields": [{
                        "path": ["$.vc.type"],
                        "filter": {"type": "array", "contains": "X509Credential"}
                    }]
                }
            }]
        }
    }
    offer_json = json.dumps(credential_offer)
    encoded = base64.urlsafe_b64encode(offer_json.encode()).decode()
    return RedirectResponse(f"http://localhost:8051/present?credential_offer_uri={encoded}&state={state}")

@app.post("/callback")
@app.get("/callback")
def login_callback(request: Request, data: str = None):
    user_info = "unknown"
    if data:
        decoded = base64.urlsafe_b64decode(data + '===').decode()
        user_info = json.loads(decoded)

    session_id = str(uuid4())
    sessions[session_id] = user_info
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie("session_id", session_id)
    return response

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    session_id = request.cookies.get("session_id")
    user_info = sessions.get(session_id)

    if not user_info:
        return RedirectResponse("/")

    return HTMLResponse(f"""
        <h1>Welcome!</h1>
        <pre>{json.dumps(user_info, indent=2)}</pre>
        <a href='/'>Log out</a>
    """)
