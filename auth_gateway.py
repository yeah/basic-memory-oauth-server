"""
auth_gateway.py - Minimal single-user OAuth 2.1 gateway in front of Basic Memory.

STAGE 3 (final): Discovery + /authorize + /token (PKCE-S256) + token-verified
reverse proxy to the local Basic Memory MCP server.

Flow:
    Web client -> https://<BASE_URL>/mcp  -> this gateway
        - validates the Bearer JWT
        - on success, transparently proxies to UPSTREAM_URL (Basic Memory)
        - streams responses (SSE / chunked) back to the client

Required packages (on Uberspace):
    uv sync   # installs all dependencies from pyproject.toml

Configuration is read from a .env file located next to this script.
See .env.example for all available keys.
"""

import base64
import hashlib
import os
import secrets
import time
from pathlib import Path

from dotenv import load_dotenv

# Load .env from the same directory as this script, regardless of CWD.
load_dotenv(Path(__file__).resolve().parent / ".env")

import httpx
import jwt  # pyjwt
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from starlette.routing import Route

# --- Configuration (from .env) ------------------------------------------------

BASE_URL = os.environ.get("BASE_URL", "https://ubernaut.uber.space").rstrip("/")
RESOURCE_URL = f"{BASE_URL}/mcp"
SCOPES = ["mcp"]

PORT = int(os.environ.get("PORT", "8001"))
CLIENT_ID = os.environ.get("CLIENT_ID", "basic-memory")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "")
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")

# Upstream Basic Memory MCP server (local, no auth of its own).
UPSTREAM_URL = os.environ.get("UPSTREAM_URL", "http://127.0.0.1:8000").rstrip("/")

ACCESS_TOKEN_TTL = int(os.environ.get("ACCESS_TOKEN_TTL", "3600"))          # 1 hour
REFRESH_TOKEN_TTL = int(os.environ.get("REFRESH_TOKEN_TTL", str(60 * 60 * 24 * 30)))  # 30 days
AUTH_CODE_TTL = int(os.environ.get("AUTH_CODE_TTL", "300"))                 # 5 minutes

# In-memory stores. Perfectly fine for single-user; after a restart you simply
# re-authenticate once (a new refresh token is then issued).
_auth_codes: dict[str, dict] = {}      # code -> {challenge, redirect_uri, expires, scope}
_refresh_tokens: dict[str, dict] = {}  # token -> {expires}

# Shared async HTTP client for proxying (created on startup).
_client: httpx.AsyncClient | None = None

# Hop-by-hop headers that must not be forwarded.
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host",
}


# --- Helpers ------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _verify_pkce(verifier: str, challenge: str) -> bool:
    """S256: BASE64URL(SHA256(verifier)) == challenge"""
    digest = hashlib.sha256(verifier.encode()).digest()
    return secrets.compare_digest(_b64url(digest), challenge)


def _issue_access_token() -> str:
    now = int(time.time())
    payload = {
        "iss": BASE_URL,
        "sub": "user",          # single user
        "aud": RESOURCE_URL,      # audience = our MCP endpoint
        "scope": " ".join(SCOPES),
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def _verify_access_token(req_headers) -> bool:
    """Validate the incoming Bearer JWT (signature, exp, iss, aud)."""
    auth = req_headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return False
    token_str = auth[7:]
    try:
        jwt.decode(
            token_str,
            JWT_SECRET,
            algorithms=["HS256"],
            audience=RESOURCE_URL,
            issuer=BASE_URL,
        )
        return True
    except jwt.PyJWTError:
        return False


# --- Discovery (Stage 1) ------------------------------------------------------

async def protected_resource_metadata(request):
    return JSONResponse({
        "resource": RESOURCE_URL,
        "authorization_servers": [BASE_URL],
        "scopes_supported": SCOPES,
        "bearer_methods_supported": ["header"],
    })


async def authorization_server_metadata(request):
    return JSONResponse({
        "issuer": BASE_URL,
        "authorization_endpoint": f"{BASE_URL}/authorize",
        "token_endpoint": f"{BASE_URL}/token",
        "scopes_supported": SCOPES,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post", "client_secret_basic", "none",
        ],
    })


# --- /authorize ---------------------------------------------------------------
# GET: shows the login form. POST: checks the password, issues an auth code.

_LOGIN_FORM = """
<!doctype html><html><head><meta charset="utf-8"><title>MCP Login</title>
<style>body{{font-family:sans-serif;max-width:380px;margin:80px auto;padding:0 16px}}
input{{width:100%;padding:10px;margin:8px 0;box-sizing:border-box}}
button{{padding:10px 16px;cursor:pointer}}</style></head>
<body><h2>Basic Memory - Login</h2>
{error}
<form method="post">
  <input type="hidden" name="client_id" value="{client_id}">
  <input type="hidden" name="redirect_uri" value="{redirect_uri}">
  <input type="hidden" name="state" value="{state}">
  <input type="hidden" name="code_challenge" value="{code_challenge}">
  <input type="hidden" name="scope" value="{scope}">
  <input type="password" name="password" placeholder="Password" autofocus>
  <button type="submit">Sign in</button>
</form></body></html>
"""


async def authorize(request):
    if request.method == "GET":
        p = request.query_params
        # Required-parameter check (PKCE is mandatory)
        if p.get("client_id") != CLIENT_ID:
            return JSONResponse({"error": "invalid_client"}, status_code=400)
        if p.get("code_challenge_method") != "S256":
            return JSONResponse(
                {"error": "invalid_request", "error_description": "PKCE S256 required"},
                status_code=400,
            )
        if not p.get("code_challenge") or not p.get("redirect_uri"):
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        html = _LOGIN_FORM.format(
            error="",
            client_id=p.get("client_id", ""),
            redirect_uri=p.get("redirect_uri", ""),
            state=p.get("state", ""),
            code_challenge=p.get("code_challenge", ""),
            scope=p.get("scope", "mcp"),
        )
        return HTMLResponse(html)

    # POST: verify login
    form = await request.form()
    if not secrets.compare_digest(form.get("password", ""), LOGIN_PASSWORD):
        html = _LOGIN_FORM.format(
            error='<p style="color:#c00">Wrong password</p>',
            client_id=form.get("client_id", ""),
            redirect_uri=form.get("redirect_uri", ""),
            state=form.get("state", ""),
            code_challenge=form.get("code_challenge", ""),
            scope=form.get("scope", "mcp"),
        )
        return HTMLResponse(html, status_code=401)

    # Issue authorization code
    code = secrets.token_urlsafe(32)
    _auth_codes[code] = {
        "challenge": form.get("code_challenge", ""),
        "redirect_uri": form.get("redirect_uri", ""),
        "scope": form.get("scope", "mcp"),
        "expires": time.time() + AUTH_CODE_TTL,
    }
    redirect_uri = form.get("redirect_uri", "")
    state = form.get("state", "")
    sep = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{sep}code={code}"
    if state:
        location += f"&state={state}"
    return RedirectResponse(location, status_code=302)


# --- /token -------------------------------------------------------------------

async def token(request):
    form = await request.form()
    grant_type = form.get("grant_type")

    # Client authentication (secret via POST body or Basic header)
    client_id = form.get("client_id")
    client_secret = form.get("client_secret")
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth_header[6:]).decode()
            client_id, client_secret = decoded.split(":", 1)
        except Exception:
            pass

    if client_id != CLIENT_ID or not secrets.compare_digest(
        client_secret or "", CLIENT_SECRET
    ):
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    if grant_type == "authorization_code":
        code = form.get("code", "")
        entry = _auth_codes.pop(code, None)
        if not entry or entry["expires"] < time.time():
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        # Verify PKCE
        verifier = form.get("code_verifier", "")
        if not _verify_pkce(verifier, entry["challenge"]):
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "PKCE failed"},
                status_code=400,
            )
        refresh = secrets.token_urlsafe(32)
        _refresh_tokens[refresh] = {"expires": time.time() + REFRESH_TOKEN_TTL}
        return JSONResponse({
            "access_token": _issue_access_token(),
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL,
            "refresh_token": refresh,
            "scope": entry["scope"],
        })

    if grant_type == "refresh_token":
        rt = form.get("refresh_token", "")
        entry = _refresh_tokens.get(rt)
        if not entry or entry["expires"] < time.time():
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        # Refresh-token rotation
        _refresh_tokens.pop(rt, None)
        new_refresh = secrets.token_urlsafe(32)
        _refresh_tokens[new_refresh] = {"expires": time.time() + REFRESH_TOKEN_TTL}
        return JSONResponse({
            "access_token": _issue_access_token(),
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL,
            "refresh_token": new_refresh,
            "scope": " ".join(SCOPES),
        })

    return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)


# --- Reverse proxy to Basic Memory (token-protected) --------------------------

def _401() -> Response:
    www_auth = (
        f'Bearer realm="mcp", '
        f'resource_metadata="{BASE_URL}/.well-known/oauth-protected-resource"'
    )
    return Response(status_code=401, headers={"WWW-Authenticate": www_auth})


async def proxy(request):
    # 1. Require a valid Bearer token.
    if not _verify_access_token(request.headers):
        return _401()

    # 2. Build the upstream request, preserving path + query.
    upstream_path = request.url.path  # e.g. /mcp
    url = f"{UPSTREAM_URL}{upstream_path}"
    if request.url.query:
        url += f"?{request.url.query}"

    # Forward headers except hop-by-hop and the Authorization (upstream has no auth).
    fwd_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP and k.lower() != "authorization"
    }

    body = await request.body()

    # 3. Open a streaming request to upstream so SSE/chunked responses pass through.
    req = _client.build_request(
        request.method, url, headers=fwd_headers, content=body,
    )
    upstream = await _client.send(req, stream=True)

    resp_headers = {
        k: v for k, v in upstream.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }

    return StreamingResponse(
        upstream.aiter_raw(),
        status_code=upstream.status_code,
        headers=resp_headers,
        background=BackgroundTask(upstream.aclose),
    )


# --- App lifecycle ------------------------------------------------------------

from contextlib import asynccontextmanager


@asynccontextmanager
async def _lifespan(app):
    global _client
    # No total timeout: MCP streams can stay open a long time.
    _client = httpx.AsyncClient(timeout=httpx.Timeout(None, connect=10.0))
    try:
        yield
    finally:
        if _client is not None:
            await _client.aclose()


routes = [
    Route("/.well-known/oauth-protected-resource",
          protected_resource_metadata, methods=["GET"]),
    Route("/.well-known/oauth-authorization-server",
          authorization_server_metadata, methods=["GET"]),
    Route("/authorize", authorize, methods=["GET", "POST"]),
    Route("/token", token, methods=["POST"]),
    # Everything else is proxied (token-protected): /mcp and any sub-path.
    Route("/{path:path}", proxy, methods=["GET", "POST", "DELETE", "PUT", "PATCH"]),
]

app = Starlette(routes=routes, lifespan=_lifespan)

# Startup check: surface missing secrets early
for _name, _val in [("CLIENT_SECRET", CLIENT_SECRET),
                    ("JWT_SECRET", JWT_SECRET),
                    ("LOGIN_PASSWORD", LOGIN_PASSWORD)]:
    if not _val:
        print(f"WARNING: {_name} is not set (check your .env)!")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
