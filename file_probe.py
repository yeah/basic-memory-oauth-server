"""
file_probe.py - Diagnostic MCP endpoint for the draft file-uploads extension.

Purpose: find out whether an MCP client (Claude, ChatGPT, ...) can hand a file
to a tool WITHOUT the model having to emit the bytes as tokens. The endpoint
offers two tools:

  probe_file    takes one file argument marked with `x-mcp-file` and reports
                how the file arrived (inline, out of band, or not at all).
                The file is checked (size, SHA-256) and then deleted. Nothing
                is written to the Basic Memory project.
  probe_status  reports what the server has seen from the client so far:
                protocol era and version, client info, declared capabilities.
                Works even when the client cannot use probe_file.

Extension draft (pinned revision, the design may still change):
  https://github.com/modelcontextprotocol/experimental-ext-file-uploads
  commit 8a859b8f268926fe4beb84d78565e7cc6f9fa617 (2026-11-09)

The endpoint is a small hand-written MCP server instead of an SDK server, for
two reasons: the draft needs a result type (`upload_required`) and a schema
keyword (`x-mcp-file`) that SDKs do not know yet, and a probe should show the
exact messages a client sends.

It is "dual-era" (see MCP 2026-07-28, Versioning and Compatibility):
  - modern:  per-request `_meta`, `server/discover`, no session
  - legacy:  `initialize` handshake (2025-03-26 .. 2025-11-25), served
             statelessly without a session id

The extension is defined for the modern era only. Out-of-band upload is
therefore offered only to modern requests that declare it.

This module has no configuration of its own beyond the FILE_PROBE_* keys and
no import of auth_gateway: the gateway passes in what it needs (see
`build_routes`), which keeps the import graph acyclic.
"""

import base64
import binascii
import hashlib
import json
import os
import secrets
import tempfile
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import jwt  # pyjwt
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

# --- Configuration ------------------------------------------------------------

# Largest file the probe accepts, inline or out of band.
MAX_BYTES = int(os.environ.get("FILE_PROBE_MAX_BYTES", str(25 * 1024 * 1024)))
# Largest total of inline `data` in one request (advertised as maxInlineBytes).
MAX_INLINE_BYTES = int(os.environ.get("FILE_PROBE_MAX_INLINE_BYTES", str(1024 * 1024)))
# Lifetime of an upload target and of the requestState issued with it.
STATE_TTL = int(os.environ.get("FILE_PROBE_TTL", "600"))  # seconds
# Where bytes wait between the transfer and the retry. Not the notes folder.
STAGING_DIR = Path(
    os.environ.get("FILE_PROBE_DIR", str(Path(tempfile.gettempdir()) / "bm-file-probe"))
)
# Upper bound on targets that are issued but not yet finished (bounds disk use).
MAX_PENDING = 8

EXTENSION_ID = "io.modelcontextprotocol/files"
META_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_CLIENT_CAPS = "io.modelcontextprotocol/clientCapabilities"
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"

MODERN_VERSIONS = ["2026-07-28"]
LEGACY_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26"]

SERVER_INFO = {"name": "basic-memory-file-probe", "version": "0.1.0"}
INSTRUCTIONS = (
    "Diagnostic server. `probe_file` tests whether this client can pass a file "
    "to a tool through the draft MCP file-uploads extension; `probe_status` "
    "shows what the server has observed about the client. No file is kept."
)

# JSON-RPC / MCP error codes.
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
HEADER_MISMATCH = -32020
MISSING_CLIENT_CAPABILITY = -32021
UNSUPPORTED_VERSION = -32022

# Audience of the signed requestState. Different from the access-token
# audience, so a requestState can never pass as an access token or vice versa.
STATE_AUDIENCE = "file-probe-request-state"
UPLOAD_TOKEN_HEADER = "X-Probe-Upload-Token"

FILE_ARGUMENT_SCHEMA = {
    "type": "object",
    "description": (
        "The file to test with. The client is expected to fill this argument "
        "itself from a file the user or agent selected."
    ),
    "x-mcp-file": {"maxSize": MAX_BYTES},
    "properties": {
        "id": {"type": "string", "minLength": 1, "maxLength": 128},
        "name": {"type": "string"},
        "mimeType": {"type": "string"},
        "size": {"type": "integer", "minimum": 0},
        "digest": {
            "type": "object",
            "properties": {
                "algorithm": {"const": "sha-256"},
                "value": {"type": "string"},
            },
            "required": ["algorithm", "value"],
        },
        "data": {"type": "string"},
    },
    "required": ["id", "mimeType", "size"],
}

TOOLS = [
    {
        "name": "probe_file",
        "title": "File upload probe",
        "description": (
            "Diagnostic. Tests whether this MCP client supports the draft "
            "file-uploads extension (x-mcp-file). Reports how the file "
            "arrived (inline or out of band), its size and SHA-256, then "
            "deletes it. Nothing is stored. The `file` argument should be "
            "bound to a real file by the client; do not write base64 by hand "
            "except to test the inline fallback with a few bytes."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"file": FILE_ARGUMENT_SCHEMA},
            "required": ["file"],
        },
    },
    {
        "name": "probe_status",
        "title": "File upload probe status",
        "description": (
            "Diagnostic. Returns the most recent requests this probe server "
            "received: protocol era and version, client name, the "
            "capabilities and extensions the client declared, and the "
            "outcome of each probe_file call and upload. Contains no file "
            "contents and no credentials."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
]

# In-memory state, like the gateway's own stores: single user, one process.
_pending: dict[str, dict] = {}                # upload id -> staged-file record
_observations: deque[dict] = deque(maxlen=50)  # newest last


# --- Small helpers ------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _observe(event: str, **fields) -> None:
    """Record one diagnostic event (and print it for `docker compose logs`).

    Callers pass only metadata. File bytes, inline `data`, upload tokens and
    requestState never go in here.
    """
    entry = {"at": _now_iso(), "event": event, **fields}
    _observations.append(entry)
    print("file-probe: " + json.dumps(entry, ensure_ascii=False, default=str))


def _canonical(value):
    """Normalise JSON so that equal instances compare equal.

    JSON Schema instance equality ignores member order and number spelling
    (1 and 1.0 are the same number), so integral floats become ints and
    objects are serialised with sorted keys by `_args_hash`.
    """
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {k: _canonical(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_canonical(v) for v in value]
    return value


def _args_hash(arguments) -> str:
    blob = json.dumps(_canonical(arguments), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def _b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _decode_header_value(value: str) -> str:
    """Undo the `=?base64?...?=` sentinel encoding of Mcp-Name, if present."""
    if value.startswith("=?base64?") and value.endswith("?="):
        try:
            return base64.b64decode(value[9:-2], validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return value
    return value


def _sweep() -> None:
    """Drop expired staged files."""
    now = time.time()
    for upload_id in [k for k, rec in _pending.items() if rec["expires"] < now]:
        _discard(upload_id)


def _discard(upload_id: str) -> None:
    rec = _pending.pop(upload_id, None)
    if rec is not None:
        try:
            rec["path"].unlink(missing_ok=True)
        except OSError:
            pass


def _files_settings(client_caps) -> dict | None:
    """The client's settings for the files extension, or None if undeclared."""
    if not isinstance(client_caps, dict):
        return None
    extensions = client_caps.get("extensions")
    if not isinstance(extensions, dict):
        return None
    settings = extensions.get(EXTENSION_ID)
    return settings if isinstance(settings, dict) else None


def _server_capabilities() -> dict:
    return {
        "tools": {},
        "extensions": {
            EXTENSION_ID: {"upload": {}, "maxInlineBytes": MAX_INLINE_BYTES},
        },
    }


# --- JSON-RPC responses -------------------------------------------------------

def _rpc_result(req_id, result: dict, modern: bool) -> Response:
    if modern:
        result.setdefault("resultType", "complete")
        result.setdefault("_meta", {})[META_SERVER_INFO] = SERVER_INFO
    return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": result})


def _rpc_error(req_id, code: int, message: str, *, status: int = 200, data=None) -> Response:
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return JSONResponse(
        {"jsonrpc": "2.0", "id": req_id, "error": error}, status_code=status
    )


def _tool_text(req_id, payload: dict, modern: bool, *, is_error: bool = False) -> Response:
    """A CallToolResult whose single text block is a JSON report."""
    result = {
        "content": [{"type": "text", "text": json.dumps(payload, indent=2, ensure_ascii=False)}],
        "isError": is_error,
    }
    return _rpc_result(req_id, result, modern)


# --- The probe_file tool ------------------------------------------------------

def _validate_file_input(file) -> str | None:
    """Return a problem description, or None if `file` has the FileInput shape."""
    if not isinstance(file, dict):
        return "`file` is not an object"
    file_id = file.get("id")
    if not isinstance(file_id, str) or not 1 <= len(file_id) <= 128:
        return "`file.id` must be a string of 1 to 128 characters"
    if not isinstance(file.get("mimeType"), str):
        return "`file.mimeType` must be a string"
    size = file.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        return "`file.size` must be a non-negative integer"
    if "name" in file and not isinstance(file["name"], str):
        return "`file.name` must be a string"
    if size > MAX_BYTES:
        return f"file is larger than the probe limit of {MAX_BYTES} bytes"
    return None


def _digest_problem(file: dict, sha256_raw: bytes) -> str | None:
    """Check an optional client-supplied digest against the bytes we hold."""
    digest = file.get("digest")
    if digest is None:
        return None
    if not isinstance(digest, dict) or digest.get("algorithm") != "sha-256":
        return "`file.digest` must be {algorithm: 'sha-256', value: ...}"
    if not secrets.compare_digest(str(digest.get("value", "")), _b64url_nopad(sha256_raw)):
        return "`file.digest` does not match the bytes received"
    return None


def _file_report(file: dict, transfer: str, sha256_raw: bytes, received: int, ctx: dict) -> dict:
    return {
        "probe": "ok",
        "transfer": transfer,
        "file": {
            "id": file.get("id"),
            "name": file.get("name"),
            "mimeType": file.get("mimeType"),
            "declaredSize": file.get("size"),
            "receivedBytes": received,
            "sha256": sha256_raw.hex(),
            "digestSentByClient": "digest" in file,
        },
        "request": ctx,
        "note": "The file was checked and deleted. Nothing was stored.",
    }


def _call_probe_file(req_id, params: dict, ctx: dict, deps: dict) -> Response:
    modern = ctx["era"] == "modern"
    arguments = params.get("arguments")
    if not isinstance(arguments, dict):
        arguments = {}
    file = arguments.get("file")
    request_state = params.get("requestState")

    def fail(reason: str) -> Response:
        _observe("probe_file", outcome="rejected", reason=reason, **ctx)
        return _tool_text(req_id, {"probe": "failed", "reason": reason, "request": ctx},
                          modern, is_error=True)

    problem = _validate_file_input(file)
    if problem:
        return fail(problem)

    meta = {k: file.get(k) for k in ("id", "name", "mimeType", "size")}
    meta["hasData"] = "data" in file
    meta["hasDigest"] = "digest" in file

    # A retry that answers our upload request.
    if request_state is not None:
        return _finish_upload(req_id, arguments, file, request_state, ctx, meta, deps)

    size = file["size"]

    # Inline transfer. Accepted whether or not the request declared the
    # extension (the draft forbids rejecting inline data on that ground).
    if "data" in file:
        data = file["data"]
        if not isinstance(data, str):
            return fail("`file.data` is present but is not a string")
        try:
            raw = base64.b64decode(data, validate=True)
        except binascii.Error:
            return fail("`file.data` is not valid base64")
        if len(raw) > MAX_INLINE_BYTES:
            return fail(f"inline data is over maxInlineBytes ({MAX_INLINE_BYTES})")
        if len(raw) != size:
            return fail(f"`file.size` says {size} bytes but the data decodes to {len(raw)}")
        sha = hashlib.sha256(raw).digest()
        problem = _digest_problem(file, sha)
        if problem:
            return fail(problem)
        _observe("probe_file", outcome="ok", transfer="inline", file=meta, **ctx)
        return _tool_text(req_id, _file_report(file, "inline", sha, len(raw), ctx), modern)

    # An empty file has nothing to transfer.
    if size == 0:
        sha = hashlib.sha256(b"").digest()
        problem = _digest_problem(file, sha)
        if problem:
            return fail(problem)
        _observe("probe_file", outcome="ok", transfer="empty", file=meta, **ctx)
        return _tool_text(req_id, _file_report(file, "empty", sha, 0, ctx), modern)

    # Metadata only, bytes still at the client: this is a request for an
    # out-of-band upload. Only a modern request that declared `upload` gets one.
    if not modern:
        return fail(
            "The client sent file metadata without data over a legacy "
            "(initialize-based) protocol version. Out-of-band upload needs "
            "protocol 2026-07-28 or later. The argument was probably written "
            "by the model, not filled in by the client."
        )
    settings = _files_settings(ctx.get("clientCapabilities"))
    if settings is None or "upload" not in settings:
        _observe("probe_file", outcome="missing_capability", file=meta, **ctx)
        return _rpc_error(
            req_id, MISSING_CLIENT_CAPABILITY,
            "This call needs the file-uploads extension with `upload`.",
            status=400,
            data={"requiredCapabilities": {"extensions": {EXTENSION_ID: {"upload": {}}}}},
        )

    _sweep()
    if len(_pending) >= MAX_PENDING:
        return fail("too many unfinished uploads; try again in a few minutes")

    upload_id = secrets.token_urlsafe(16)
    upload_token = secrets.token_urlsafe(32)
    expires = time.time() + STATE_TTL
    STAGING_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    _pending[upload_id] = {
        "token": upload_token,
        "size": size,
        "expires": expires,
        "path": STAGING_DIR / upload_id,
        "written": False,
        "sha256": None,
    }
    mime = file["mimeType"] or "application/octet-stream"
    state = jwt.encode(
        {
            "aud": STATE_AUDIENCE,
            "sub": "user",                  # single user, as in the gateway
            "exp": int(expires),
            "tool": "probe_file",
            "args": _args_hash(arguments),
            "files": {file["id"]: upload_id},
            "uploadIssued": True,
        },
        deps["secret"], algorithm="HS256",
    )
    _observe("probe_file", outcome="upload_required", file=meta, **ctx)
    return _rpc_result(req_id, {
        "resultType": "upload_required",
        "uploads": [{
            "fileId": file["id"],
            "url": f"{deps['base_url']}/mcp-probe/upload/{upload_id}",
            "method": "PUT",
            # The target carries its own authorization: an unguessable token
            # in a header (kept out of the URL so it stays out of access logs).
            "headers": {"Content-Type": mime, UPLOAD_TOKEN_HEADER: upload_token},
            "credentials": "omit",
            "expiresAt": datetime.fromtimestamp(expires, timezone.utc)
                                 .strftime("%Y-%m-%dT%H:%M:%SZ"),
        }],
        "requestState": state,
    }, modern)


def _finish_upload(req_id, arguments, file, request_state, ctx, meta, deps) -> Response:
    """Handle the retry: verify state, confirm the bytes, report, clean up."""
    modern = ctx["era"] == "modern"

    def bad_state(reason: str) -> Response:
        _observe("probe_file", outcome="bad_request_state", reason=reason, **ctx)
        return _rpc_error(req_id, INVALID_PARAMS, f"requestState rejected: {reason}")

    if not isinstance(request_state, str):
        return bad_state("not a string")
    try:
        state = jwt.decode(request_state, deps["secret"], algorithms=["HS256"],
                           audience=STATE_AUDIENCE)
    except jwt.PyJWTError:
        return bad_state("invalid or expired")
    if state.get("tool") != "probe_file" or state.get("sub") != "user":
        return bad_state("issued for a different call")
    if not secrets.compare_digest(str(state.get("args", "")), _args_hash(arguments)):
        return bad_state("arguments differ from the original call")
    upload_id = (state.get("files") or {}).get(file["id"])
    rec = _pending.get(upload_id) if isinstance(upload_id, str) else None
    if rec is None:
        # Unknown, expired or already used (each state is accepted once).
        return bad_state("unknown or already used")

    def fail(reason: str) -> Response:
        _discard(upload_id)
        _observe("probe_file", outcome="rejected", reason=reason, file=meta, **ctx)
        return _tool_text(req_id, {"probe": "failed", "reason": reason, "request": ctx},
                          modern, is_error=True)

    if not rec["written"] or rec["sha256"] is None:
        return fail("the client sent the retry but no bytes arrived at the upload target")
    received = rec["path"].stat().st_size if rec["path"].exists() else -1
    if received != rec["size"]:
        return fail(f"upload has {received} bytes, expected {rec['size']}")
    sha = rec["sha256"]
    problem = _digest_problem(file, sha)
    if problem:
        return fail(problem)

    _discard(upload_id)  # consumes the state and deletes the staged file
    _observe("probe_file", outcome="ok", transfer="out-of-band", file=meta, **ctx)
    return _tool_text(req_id, _file_report(file, "out-of-band", sha, received, ctx), modern)


def _call_probe_status(req_id, ctx: dict) -> Response:
    payload = {
        "server": SERVER_INFO,
        "extension": {
            "id": EXTENSION_ID,
            "advertised": _server_capabilities()["extensions"][EXTENSION_ID],
            "maxFileBytes": MAX_BYTES,
        },
        "thisRequest": ctx,
        "recent": list(_observations),
    }
    return _tool_text(req_id, payload, ctx["era"] == "modern")


# --- Method dispatch ----------------------------------------------------------

def _dispatch(req_id, method: str, params: dict, ctx: dict, deps: dict) -> Response:
    modern = ctx["era"] == "modern"

    if method == "tools/list":
        _observe("tools/list", filesExtensionDeclared=_files_settings(
            ctx.get("clientCapabilities")) is not None, **ctx)
        result = {"tools": TOOLS}
        if modern:
            # Do not cache: the probe may be redeployed between two tests.
            result.update({"ttlMs": 0, "cacheScope": "private"})
        return _rpc_result(req_id, result, modern)

    if method == "tools/call":
        name = params.get("name")
        if name == "probe_file":
            return _call_probe_file(req_id, params, ctx, deps)
        if name == "probe_status":
            return _call_probe_status(req_id, ctx)
        return _rpc_error(req_id, INVALID_PARAMS, f"Unknown tool: {name!r}")

    if modern and method == "server/discover":
        _observe("server/discover", **ctx)
        return _rpc_result(req_id, {
            "supportedVersions": MODERN_VERSIONS + LEGACY_VERSIONS,
            "capabilities": _server_capabilities(),
            "instructions": INSTRUCTIONS,
            "ttlMs": 0,
            "cacheScope": "private",
        }, modern)

    if not modern and method == "initialize":
        requested = params.get("protocolVersion")
        version = requested if requested in LEGACY_VERSIONS else LEGACY_VERSIONS[0]
        _observe("initialize", requestedVersion=requested, negotiatedVersion=version,
                 clientInfo=params.get("clientInfo"),
                 clientCapabilities=params.get("capabilities"))
        return _rpc_result(req_id, {
            "protocolVersion": version,
            "capabilities": _server_capabilities(),
            "serverInfo": SERVER_INFO,
            "instructions": INSTRUCTIONS,
        }, modern)

    if not modern and method == "ping":
        return _rpc_result(req_id, {}, modern)

    _observe("unknown_method", method=method, **ctx)
    # Modern servers answer an unknown method with 404 plus a JSON-RPC error.
    return _rpc_error(req_id, METHOD_NOT_FOUND, f"Method not found: {method}",
                      status=404 if modern else 200)


def _modern_precheck(request, req_id, method: str, params: dict) -> Response | None:
    """Header and metadata validation required of a modern server.

    Returns an error response, or None if the request is acceptable.
    """
    meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
    header_version = request.headers.get("mcp-protocol-version")
    body_version = meta.get(META_VERSION)

    def reject(code: int, message: str, data=None) -> Response:
        _observe("rejected", method=method, code=code, reason=message,
                 headerVersion=header_version, bodyVersion=body_version,
                 clientInfo=meta.get(META_CLIENT_INFO))
        return _rpc_error(req_id, code, message, status=400, data=data)

    if body_version is None:
        return reject(INVALID_PARAMS, f"Missing {META_VERSION} in _meta")
    if header_version is None:
        return reject(HEADER_MISMATCH, "Missing MCP-Protocol-Version header")
    if header_version != body_version:
        return reject(HEADER_MISMATCH, "MCP-Protocol-Version header does not match _meta")
    if body_version not in MODERN_VERSIONS:
        return reject(UNSUPPORTED_VERSION, "Unsupported protocol version",
                      {"supported": MODERN_VERSIONS + LEGACY_VERSIONS,
                       "requested": body_version})
    if not isinstance(meta.get(META_CLIENT_CAPS), dict):
        return reject(INVALID_PARAMS, f"Missing {META_CLIENT_CAPS} in _meta")
    header_method = request.headers.get("mcp-method")
    if header_method is None:
        return reject(HEADER_MISMATCH, "Missing Mcp-Method header")
    if header_method != method:
        return reject(HEADER_MISMATCH, "Mcp-Method header does not match the request body")
    if method == "tools/call":
        header_name = request.headers.get("mcp-name")
        if header_name is None:
            return reject(HEADER_MISMATCH, "Missing Mcp-Name header")
        if _decode_header_value(header_name) != params.get("name"):
            return reject(HEADER_MISMATCH, "Mcp-Name header does not match the request body")
    return None


# --- HTTP handlers ------------------------------------------------------------

def build_routes(*, base_url: str, secret: str, verify_bearer, unauthorized) -> list[Route]:
    """Create the probe's routes.

    base_url       public base URL of the gateway, without a trailing slash
    secret         key for signing requestState (the gateway's JWT secret)
    verify_bearer  callable(headers) -> bool, the gateway's access-token check
    unauthorized   callable() -> Response, the 401 that starts OAuth discovery
    """
    deps = {"base_url": base_url, "secret": secret}

    async def mcp_endpoint(request):
        if not verify_bearer(request.headers):
            return unauthorized()
        if request.method != "POST":
            # No GET stream and no sessions on this endpoint.
            return Response(status_code=405, headers={"Allow": "POST"})
        try:
            message = json.loads(await request.body())
        except ValueError:
            return _rpc_error(None, -32700, "Parse error", status=400)
        if not isinstance(message, dict) or not isinstance(message.get("method"), str):
            return _rpc_error(None, INVALID_REQUEST, "Expected one JSON-RPC request",
                              status=400)

        method = message["method"]
        req_id = message.get("id")
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}

        if "id" not in message:
            # A notification (e.g. notifications/initialized). Nothing to do.
            return Response(status_code=202)

        # Era: `initialize` always opens a legacy conversation. Otherwise a
        # request is modern if it carries the per-request version in `_meta`,
        # or names a modern version in the header.
        modern = method != "initialize" and (
            META_VERSION in meta
            or request.headers.get("mcp-protocol-version") in MODERN_VERSIONS
        )
        if modern:
            error = _modern_precheck(request, req_id, method, params)
            if error is not None:
                return error
            ctx = {
                "era": "modern",
                "protocolVersion": meta.get(META_VERSION),
                "clientInfo": meta.get(META_CLIENT_INFO),
                "clientCapabilities": meta.get(META_CLIENT_CAPS),
            }
        else:
            ctx = {
                "era": "legacy",
                "protocolVersion": request.headers.get("mcp-protocol-version"),
            }
        return _dispatch(req_id, method, params, ctx, deps)

    async def upload_endpoint(request):
        """Upload target named in an `upload_required` result.

        Authorized by the per-upload token header, not by the OAuth bearer
        (the target is issued with `credentials: "omit"`). Accepts one write
        of exactly the declared size.
        """
        _sweep()
        upload_id = request.path_params["upload_id"]
        rec = _pending.get(upload_id)
        token = request.headers.get(UPLOAD_TOKEN_HEADER, "")
        if rec is None or not secrets.compare_digest(token, rec["token"]):
            _observe("upload", outcome="refused", reason="unknown target or wrong token")
            return Response(status_code=403)
        if rec["written"]:
            _observe("upload", outcome="refused", reason="target already used")
            return Response(status_code=409)

        rec["written"] = True  # one write per target, even if this one fails
        digest = hashlib.sha256()
        received = 0
        try:
            with open(rec["path"], "wb") as out:
                async for chunk in request.stream():
                    received += len(chunk)
                    if received > rec["size"]:
                        break
                    digest.update(chunk)
                    out.write(chunk)
        except OSError:
            _discard(upload_id)
            _observe("upload", outcome="failed", reason="could not write staging file")
            return Response(status_code=500)
        if received != rec["size"]:
            _discard(upload_id)
            _observe("upload", outcome="refused", declaredSize=rec["size"],
                     reason="body size differs from the declared size")
            return Response(status_code=413 if received > rec["size"] else 400)

        rec["sha256"] = digest.digest()
        _observe("upload", outcome="stored", bytes=received,
                 contentType=request.headers.get("content-type"))
        return Response(status_code=204)

    async def protected_resource_metadata(request):
        # RFC 9728 path-specific metadata for the probe endpoint, so a client
        # that checks `resource` against the URL it connects to is satisfied.
        return JSONResponse({
            "resource": f"{base_url}/mcp-probe",
            "resource_name": "Basic Memory file probe",
            "authorization_servers": [base_url],
            "scopes_supported": ["mcp"],
            "bearer_methods_supported": ["header"],
        })

    return [
        Route("/.well-known/oauth-protected-resource/mcp-probe",
              protected_resource_metadata, methods=["GET"]),
        Route("/mcp-probe", mcp_endpoint, methods=["GET", "POST", "DELETE"]),
        Route("/mcp-probe/upload/{upload_id}", upload_endpoint, methods=["PUT"]),
    ]
