"""
auth_gateway.py - Single-user gateway in front of Basic Memory and WsgiDAV.

One public entrypoint, two auth schemes by path:
  /mcp  -> OAuth 2.1 + PKCE (Bearer JWT)  -> proxy to Basic Memory (MCP)
  /dav  -> HTTP Basic Auth                -> proxy to WsgiDAV (WebDAV)

Both share one set of credentials from .env: the OAuth client id doubles as the
WebDAV username, and LOGIN_PASSWORD covers both the OAuth login and WebDAV Basic
Auth. The upstreams have no auth of their own and bind 127.0.0.1 only.

Required packages (on Uberspace):
    uv sync   # installs all dependencies from pyproject.toml

Configuration is read from a .env file located next to this script.
See .env.example for all available keys.
"""

import base64
import hashlib
import html
import os
import secrets
import time
from collections import deque
from pathlib import Path
from urllib.parse import urlsplit

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

# Basic Memory logo, referenced directly from basicmemory.com (not downloaded
# or re-hosted). Shown on the login page, advertised in resource metadata, and
# used as the /favicon.ico redirect target.
LOGO_URI = os.environ.get(
    "LOGO_URI",
    "https://basicmemory.com/images/basic-memory/disk-logo-black.svg",
)

PORT = int(os.environ.get("PORT", "8001"))
CLIENT_ID = os.environ.get("CLIENT_ID", "basic-memory")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "")
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")

# Brute-force throttle for the human-chosen LOGIN_PASSWORD (used at /authorize
# and /dav). After AUTH_FAIL_LIMIT failed attempts within AUTH_FAIL_WINDOW
# seconds, further attempts get 429 until the window cools down. The counter is
# GLOBAL (not per-IP): behind the reverse proxy the real client IP is not
# trustworthy (X-Forwarded-For is spoofable, and a forged one could lock out
# the legitimate user), so a global limit is the robust choice. Trade-off: an
# attacker actively guessing can also lock the legitimate user out for the
# (short, self-expiring) window. Set AUTH_FAIL_LIMIT=0 to disable.
AUTH_FAIL_LIMIT = int(os.environ.get("AUTH_FAIL_LIMIT", "10"))
AUTH_FAIL_WINDOW = int(os.environ.get("AUTH_FAIL_WINDOW", "300"))  # seconds

# Exact-match allowlist of OAuth redirect URIs (comma-separated in .env).
# The authorization code is only ever handed to a URI allowed here (or by
# ALLOWED_REDIRECT_HOSTS below), which stops an attacker from driving the flow
# to their own callback. If neither list allows the URI it is rejected (fail
# closed) and logged, so you can copy the exact value your client uses.
ALLOWED_REDIRECT_URIS = [
    _u.strip()
    for _u in os.environ.get("ALLOWED_REDIRECT_URIS", "").split(",")
    if _u.strip()
]

# Host-based allowlist (comma-separated in .env). A redirect URI is accepted if
# it is an https URL whose host EXACTLY matches one of these. This covers
# clients that generate a per-connector callback path on a fixed host, e.g.
# ChatGPT's https://chatgpt.com/connector/oauth/<id>: pinning the host is the
# real security boundary (that is where the code is delivered), while the path
# may vary. Exact host match only (no subdomain wildcards), so a lookalike like
# chatgpt.com.evil.com or chatgpt.com@evil.com is rejected.
ALLOWED_REDIRECT_HOSTS = [
    _h.strip().lower()
    for _h in os.environ.get("ALLOWED_REDIRECT_HOSTS", "").split(",")
    if _h.strip()
]

# Upstream Basic Memory MCP server (local, no auth of its own).
UPSTREAM_URL = os.environ.get("UPSTREAM_URL", "http://127.0.0.1:8000").rstrip("/")

# Upstream WebDAV server (WsgiDAV, local, no auth of its own). Used for the
# /dav path, which Obsidian and other WebDAV clients reach via Basic Auth.
DAV_UPSTREAM_URL = os.environ.get("DAV_UPSTREAM_URL", "http://127.0.0.1:8002").rstrip("/")

# WebDAV Basic Auth uses the same credentials as OAuth: the username equals
# CLIENT_ID and the password equals LOGIN_PASSWORD, so everything is driven by
# a single set of secrets in .env.
WEBDAV_USERNAME = os.environ.get("WEBDAV_USERNAME", CLIENT_ID)

ACCESS_TOKEN_TTL = int(os.environ.get("ACCESS_TOKEN_TTL", "3600"))          # 1 hour
REFRESH_TOKEN_TTL = int(os.environ.get("REFRESH_TOKEN_TTL", str(60 * 60 * 24 * 30)))  # 30 days
AUTH_CODE_TTL = int(os.environ.get("AUTH_CODE_TTL", "300"))                 # 5 minutes

# In-memory stores. Perfectly fine for single-user; after a restart you simply
# re-authenticate once (a new refresh token is then issued).
_auth_codes: dict[str, dict] = {}      # code -> {challenge, redirect_uri, expires, scope}
_refresh_tokens: dict[str, dict] = {}  # token -> {expires}
# Timestamps of recent failed auth attempts (bounded to the limit), for the
# global brute-force throttle. Only failures are recorded; success clears it.
_auth_fail_times: deque[float] = deque(maxlen=max(1, AUTH_FAIL_LIMIT))

# Shared async HTTP client for proxying (created on startup).
_client: httpx.AsyncClient | None = None

# Hop-by-hop headers that must not be forwarded.
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host",
}


# --- Helpers ------------------------------------------------------------------

def _esc(value: str) -> str:
    """HTML-escape a value for safe interpolation into the login page,
    including quotes so it is safe inside HTML attributes."""
    return html.escape(value, quote=True)


def _throttle_retry_after() -> int:
    """Seconds the caller must wait if the failed-auth limit is exceeded, else 0.

    Global sliding window: failures older than AUTH_FAIL_WINDOW are dropped; if
    AUTH_FAIL_LIMIT failures remain within the window, return how long until the
    oldest of them ages out. Returns 0 when throttling is disabled or under the
    limit.
    """
    if AUTH_FAIL_LIMIT <= 0:
        return 0
    now = time.time()
    cutoff = now - AUTH_FAIL_WINDOW
    while _auth_fail_times and _auth_fail_times[0] < cutoff:
        _auth_fail_times.popleft()
    if len(_auth_fail_times) < AUTH_FAIL_LIMIT:
        return 0
    return max(1, int(_auth_fail_times[0] + AUTH_FAIL_WINDOW - now))


def _record_auth_failure() -> None:
    _auth_fail_times.append(time.time())


def _reset_auth_failures() -> None:
    _auth_fail_times.clear()


def _429(retry_after: int) -> Response:
    """Too Many Requests, with a Retry-After hint (seconds)."""
    return Response(status_code=429, headers={"Retry-After": str(retry_after)})


def _redirect_uri_ok(uri: str) -> bool:
    """True if uri is allowed, by either:

    1. exact full-URI match against ALLOWED_REDIRECT_URIS, or
    2. https URL whose host exactly matches an entry in ALLOWED_REDIRECT_HOSTS.

    The URL is parsed (not string-prefixed) so lookalike hosts such as
    chatgpt.com.evil.com or chatgpt.com@evil.com cannot pass the host check.
    urlsplit can raise ValueError on some malformed inputs; that is caught and
    treated as not allowed. Rejected values are logged so the operator can
    discover the exact redirect_uri (or host) their client uses and allow it.
    """
    if uri in ALLOWED_REDIRECT_URIS:
        return True
    if ALLOWED_REDIRECT_HOSTS:
        try:
            parts = urlsplit(uri)
        except ValueError:
            parts = None  # malformed URL -> treat as not allowed
        if (
            parts is not None
            and parts.scheme == "https"
            and parts.hostname
            and parts.hostname.lower() in ALLOWED_REDIRECT_HOSTS
        ):
            return True
    print(
        "rejected redirect_uri (allow its host via ALLOWED_REDIRECT_HOSTS, or "
        "the exact URI via ALLOWED_REDIRECT_URIS, if you trust it): " + repr(uri)
    )
    return False


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


# --- Discovery ----------------------------------------------------------------

async def protected_resource_metadata(request):
    return JSONResponse({
        "resource": RESOURCE_URL,
        "resource_name": "Basic Memory",
        # Referenced from basicmemory.com (not self-hosted). Optional field
        # some clients display next to the connector.
        "logo_uri": LOGO_URI,
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
<style>body{{font-family:sans-serif;max-width:380px;margin:80px auto;padding:0 16px;text-align:center}}
img.logo{{width:64px;height:64px;margin-bottom:8px}}
form{{text-align:left}}
input{{width:100%;padding:10px;margin:8px 0;box-sizing:border-box}}
button{{padding:10px 16px;cursor:pointer}}</style></head>
<body>
<img class="logo" src="{logo_uri}" alt="Basic Memory">
<h2>Basic Memory - Login</h2>
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
        if not _redirect_uri_ok(p.get("redirect_uri", "")):
            return JSONResponse(
                {"error": "invalid_request",
                 "error_description": "redirect_uri not allowed"},
                status_code=400,
            )
        html_page = _LOGIN_FORM.format(
            error="",  # server-controlled HTML, must NOT be escaped
            logo_uri=_esc(LOGO_URI),
            client_id=_esc(p.get("client_id", "")),
            redirect_uri=_esc(p.get("redirect_uri", "")),
            state=_esc(p.get("state", "")),
            code_challenge=_esc(p.get("code_challenge", "")),
            scope=_esc(p.get("scope", "mcp")),
        )
        return HTMLResponse(html_page)

    # POST: verify login
    form = await request.form()
    if not _redirect_uri_ok(form.get("redirect_uri", "")):
        return JSONResponse(
            {"error": "invalid_request",
             "error_description": "redirect_uri not allowed"},
            status_code=400,
        )
    retry = _throttle_retry_after()
    if retry:
        return _429(retry)
    if not secrets.compare_digest(form.get("password", ""), LOGIN_PASSWORD):
        _record_auth_failure()
        html_page = _LOGIN_FORM.format(
            error='<p style="color:#c00">Wrong password</p>',  # server-controlled
            logo_uri=_esc(LOGO_URI),
            client_id=_esc(form.get("client_id", "")),
            redirect_uri=_esc(form.get("redirect_uri", "")),
            state=_esc(form.get("state", "")),
            code_challenge=_esc(form.get("code_challenge", "")),
            scope=_esc(form.get("scope", "mcp")),
        )
        return HTMLResponse(html_page, status_code=401)

    _reset_auth_failures()  # successful login clears the throttle

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


# --- Reverse proxy core (shared by both auth paths) ---------------------------

def _401_bearer() -> Response:
    www_auth = (
        f'Bearer realm="mcp", '
        f'resource_metadata="{BASE_URL}/.well-known/oauth-protected-resource"'
    )
    return Response(status_code=401, headers={"WWW-Authenticate": www_auth})


def _401_basic() -> Response:
    # Prompts WebDAV clients (Obsidian) to send Basic credentials.
    return Response(
        status_code=401,
        headers={"WWW-Authenticate": 'Basic realm="webdav"'},
    )


def _check_basic_auth(req_headers) -> bool:
    """Validate Basic Auth against WEBDAV_USERNAME / LOGIN_PASSWORD."""
    auth = req_headers.get("authorization", "")
    if not auth.startswith("Basic "):
        return False
    try:
        user, pw = base64.b64decode(auth[6:]).decode().split(":", 1)
    except Exception:
        return False
    return secrets.compare_digest(user, WEBDAV_USERNAME) and secrets.compare_digest(
        pw, LOGIN_PASSWORD
    )


async def _proxy_to(request, upstream_base: str) -> Response:
    """Stream the request through to an upstream, preserving method/path/query.

    Works for plain HTTP (MCP/SSE) as well as WebDAV verbs (PROPFIND, MKCOL,
    COPY, MOVE, LOCK, ...), because the method is forwarded verbatim.
    """
    url = f"{upstream_base}{request.url.path}"
    if request.url.query:
        url += f"?{request.url.query}"

    # Forward all headers except hop-by-hop and our own Authorization
    # (the upstreams have no auth of their own).
    fwd_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP and k.lower() != "authorization"
    }

    body = await request.body()

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


# --- /mcp : OAuth-protected proxy to Basic Memory -----------------------------

async def proxy_mcp(request):
    if not _verify_access_token(request.headers):
        return _401_bearer()
    return await _proxy_to(request, UPSTREAM_URL)


# --- /dav : Basic-Auth-protected proxy to WsgiDAV -----------------------------

async def proxy_dav(request):
    # A request with no Authorization header is the normal WebDAV challenge
    # handshake, not a password guess: answer 401 without counting it.
    if not request.headers.get("authorization", "").startswith("Basic "):
        return _401_basic()
    retry = _throttle_retry_after()
    if retry:
        return _429(retry)
    if not _check_basic_auth(request.headers):
        _record_auth_failure()
        return _401_basic()
    _reset_auth_failures()  # successful auth clears the throttle
    return await _proxy_to(request, DAV_UPSTREAM_URL)


# --- /favicon.ico : redirect to the Basic Memory logo ------------------------
# Browsers and favicon services (e.g. the one Claude uses to show a connector
# icon) request /favicon.ico at the domain root. We 302-redirect to the logo
# hosted on basicmemory.com, so nothing is stored or served locally.

async def favicon(request):
    return RedirectResponse(LOGO_URI, status_code=302)


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


# All WebDAV methods Obsidian / clients may use, plus standard HTTP verbs.
_DAV_METHODS = [
    "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS",
    "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
]

routes = [
    Route("/.well-known/oauth-protected-resource",
          protected_resource_metadata, methods=["GET"]),
    Route("/.well-known/oauth-authorization-server",
          authorization_server_metadata, methods=["GET"]),
    Route("/authorize", authorize, methods=["GET", "POST"]),
    Route("/token", token, methods=["POST"]),
    Route("/favicon.ico", favicon, methods=["GET"]),
    # MCP endpoint (and any sub-path), OAuth-protected.
    Route("/mcp", proxy_mcp, methods=["GET", "POST", "DELETE"]),
    Route("/mcp/{path:path}", proxy_mcp, methods=["GET", "POST", "DELETE"]),
    # WebDAV endpoint (and any sub-path), Basic-Auth-protected.
    Route("/dav", proxy_dav, methods=_DAV_METHODS),
    Route("/dav/{path:path}", proxy_dav, methods=_DAV_METHODS),
]

app = Starlette(routes=routes, lifespan=_lifespan)

# Startup check: refuse to run without the secrets that protect every endpoint.
# Empty values would otherwise mean an empty password / empty client secret is
# accepted, i.e. a silent full auth bypass. Fail closed instead of warning.
_missing = [
    _name for _name, _val in [
        ("CLIENT_SECRET", CLIENT_SECRET),
        ("JWT_SECRET", JWT_SECRET),
        ("LOGIN_PASSWORD", LOGIN_PASSWORD),
    ] if not _val
]
if _missing:
    raise SystemExit(
        "refusing to start: missing required secret(s) in .env: "
        + ", ".join(_missing)
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
