import json
import uuid

import psycopg
from config import DATABASE_URL
import base64

def parse_jwt_unverified(token):
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    header_b64 = parts[0] + '=='
    payload_b64 = parts[1] + '=='
    header = json.loads(base64.urlsafe_b64decode(header_b64.encode()))
    payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode()))
    return header, payload

def init_db():
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id UUID PRIMARY KEY,
                    label TEXT UNIQUE NOT NULL,
                    jwt TEXT NOT NULL
                )
            """)
            conn.commit()

def store_credential_with_label(label: str, jwt_str: str):
    cred_id = str(uuid.uuid4())
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO credentials (id, label, jwt)
                VALUES (%s, %s, %s)
            """, (cred_id, label, jwt_str))
            conn.commit()
    return cred_id

def list_credentials():
    results = []
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT label, jwt FROM credentials")
            for label, jwt_str in cur.fetchall():
                try:
                    _, payload = parse_jwt_unverified(jwt_str)
                    vc = payload.get("vc", {})
                    types = vc.get("type", [])
                    if isinstance(types, str):
                        types = [types]
                    subject = vc.get("credentialSubject", [{}])[0].get("id", "unknown")
                    issuer = payload.get("iss", "unknown")
                except Exception:
                    types = ["invalid"]
                    subject = "error"
                    issuer = "error"
                results.append({
                    "label": label,
                    "types": types,
                    "subject": subject,
                    "issuer": issuer
                })
    return results

def find_credential_by_type(vc_type: str):
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT jwt FROM credentials")
            for (jwt_str,) in cur.fetchall():
                # naive check: match `vc.type` inside payload
                from jose import jwt
                payload = jwt.get_unverified_claims(jwt_str)
                if vc_type in payload.get("vc", {}).get("type", []):
                    return jwt_str
    return None


def init_did_table():
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS dids (
                    id UUID PRIMARY KEY,
                    label TEXT UNIQUE NOT NULL,
                    did TEXT NOT NULL,
                    public_jwk JSONB NOT NULL,
                    private_jwk JSONB NOT NULL
                )
            """)
            conn.commit()

def store_did(label: str, did: str, public_jwk: dict, private_jwk: dict):
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO dids (id, label, did, public_jwk, private_jwk)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                str(uuid.uuid4()),
                label,
                did,
                json.dumps(public_jwk),
                json.dumps(private_jwk)
            ))
            conn.commit()

def list_dids():
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT label, did, public_jwk FROM dids")
            return [
                {
                    "label": row[0],
                    "did": row[1],
                    "kty": json.loads(row[2]).get("kty", "?")
                } for row in cur.fetchall()
            ]



def get_credential_by_label(label: str):
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT jwt FROM credentials WHERE label = %s", (label,))
            row = cur.fetchone()
            return row[0] if row else None

def get_did_keypair_by_label(label: str):
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT did, private_jwk FROM dids WHERE label = %s", (label,))
            row = cur.fetchone()
            if not row:
                return None
            return {
                "did": row[0],
                "private_jwk": json.loads(row[1])
            }
