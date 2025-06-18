from typing import Optional

from pydantic import BaseModel

class Credential(BaseModel):
    id: str  # UUID
    jwt: str

class CreateDIDRequest(BaseModel):
    label: str

class AddCredentialRequest(BaseModel):
    label: str
    jwt: str

class PresentRequest(BaseModel):
    credential_label: str
    holder_label: str
    audience: Optional[str] = None  # optional verifier URL