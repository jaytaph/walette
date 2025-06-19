import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from uuid import uuid4
import base64
import json

app = FastAPI()
templates = Jinja2Templates(directory="templates")

sessions = {}

@app.get("/", response_class=HTMLResponse)
def login_screen(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    async with httpx.AsyncClient() as client:
        resp = await client.post("http://localhost:8052/openid4vp/initiate", json={
            "redirect_uri": f"{request.url.scheme}://{request.url.hostname}:{request.url.port}/callback",
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
        })

    data = resp.json()
    request_uri = data["request_uri"]
    deep_link = f"openid4vp://?request_uri={request_uri}"

    html = f"""
    <html>
    <body>
      <h1>Login via Wallet</h1>
      <p>Scan this with your wallet:</p>
      <code>{deep_link}</code>
      <br/><br/>
      <a href="{deep_link}">Open in wallet</a>
      <br/><br/>
      <p>Request URI: <a href="{request_uri}" target="_blank">{request_uri}</a></p>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

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
