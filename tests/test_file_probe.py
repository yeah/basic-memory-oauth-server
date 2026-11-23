"""Tests for the diagnostic file-upload probe (file_probe.py).

The test client plays the part of an MCP client. Each test follows one path
through the draft file-uploads extension. Run with: uv run pytest
"""

import base64
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

# The gateway reads its configuration at import time, so set it first.
os.environ.update({
    "BASE_URL": "https://memory.test",
    "CLIENT_SECRET": "test-client-secret",
    "JWT_SECRET": "test-jwt-secret-with-enough-length-for-hs256",
    "LOGIN_PASSWORD": "test-password",
    "FILE_PROBE_ENABLED": "1",
    "FILE_PROBE_MAX_BYTES": "4096",
    "FILE_PROBE_MAX_INLINE_BYTES": "64",
})
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from starlette.testclient import TestClient  # noqa: E402

import auth_gateway  # noqa: E402
import file_probe  # noqa: E402

MODERN = "2026-07-28"
FILES = "io.modelcontextprotocol/files"
UPLOAD_CAPS = {"extensions": {FILES: {"upload": {}}}}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(file_probe, "STAGING_DIR", tmp_path / "staging")
    file_probe._pending.clear()
    file_probe._observations.clear()
    # base_url makes the client treat https://memory.test/... as this app.
    with TestClient(auth_gateway.app, base_url="https://memory.test") as c:
        c.headers["Authorization"] = "Bearer " + auth_gateway._issue_access_token()
        yield c


def modern_call(client, method, params=None, *, caps=None, req_id=1, headers=None):
    """Send one modern (2026-07-28) request with the required metadata."""
    params = dict(params or {})
    params["_meta"] = {
        "io.modelcontextprotocol/protocolVersion": MODERN,
        "io.modelcontextprotocol/clientInfo": {"name": "pytest", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": caps if caps is not None else {},
    }
    send = {"MCP-Protocol-Version": MODERN, "Mcp-Method": method}
    if method == "tools/call":
        send["Mcp-Name"] = params["name"]
    send.update(headers or {})
    return client.post(
        "/mcp-probe",
        json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": params},
        headers=send,
    )


def report(response):
    """The JSON report inside a tool result's text block."""
    return json.loads(response.json()["result"]["content"][0]["text"])


def file_arg(content: bytes, *, inline=False, **extra):
    arg = {"id": "file-1", "name": "note.pdf", "mimeType": "application/pdf",
           "size": len(content), **extra}
    if inline:
        arg["data"] = base64.b64encode(content).decode()
    return arg


# --- Access control -----------------------------------------------------------

def test_requires_bearer_token_and_points_to_probe_metadata(client):
    r = client.post("/mcp-probe", json={}, headers={"Authorization": ""})
    assert r.status_code == 401
    assert "/.well-known/oauth-protected-resource/mcp-probe" in r.headers["www-authenticate"]

    meta = client.get("/.well-known/oauth-protected-resource/mcp-probe").json()
    assert meta["resource"] == "https://memory.test/mcp-probe"
    assert meta["authorization_servers"] == ["https://memory.test"]


def test_main_endpoint_metadata_is_unchanged(client):
    meta = client.get("/.well-known/oauth-protected-resource").json()
    assert meta["resource"] == "https://memory.test/mcp"


# --- Modern era ---------------------------------------------------------------

def test_discover_advertises_the_extension(client):
    result = modern_call(client, "server/discover").json()["result"]
    assert result["resultType"] == "complete"
    assert MODERN in result["supportedVersions"]
    settings = result["capabilities"]["extensions"][FILES]
    assert settings == {"upload": {}, "maxInlineBytes": 64}


def test_tools_list_marks_the_file_argument(client):
    result = modern_call(client, "tools/list").json()["result"]
    tools = {t["name"]: t for t in result["tools"]}
    assert set(tools) == {"probe_file", "probe_status"}
    file_schema = tools["probe_file"]["inputSchema"]["properties"]["file"]
    assert file_schema["x-mcp-file"] == {"maxSize": 4096}
    assert file_schema["required"] == ["id", "mimeType", "size"]
    assert result["ttlMs"] == 0 and result["cacheScope"] == "private"


def test_inline_file_is_reported_and_not_stored(client, tmp_path):
    content = b"%PDF-1.7 tiny"
    r = modern_call(client, "tools/call",
                    {"name": "probe_file", "arguments": {"file": file_arg(content, inline=True)}})
    body = report(r)
    assert body["probe"] == "ok" and body["transfer"] == "inline"
    assert body["file"]["receivedBytes"] == len(content)
    assert body["file"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert not (tmp_path / "staging").exists()


def test_out_of_band_upload_round_trip(client, tmp_path):
    content = os.urandom(1000)  # over maxInlineBytes, so it must go out of band
    args = {"file": file_arg(content)}

    first = modern_call(client, "tools/call", {"name": "probe_file", "arguments": args},
                        caps=UPLOAD_CAPS).json()["result"]
    assert first["resultType"] == "upload_required"
    (target,) = first["uploads"]
    assert target["fileId"] == "file-1"
    assert target["credentials"] == "omit"
    assert target["url"].startswith("https://memory.test/mcp-probe/upload/")
    assert target["headers"]["Content-Type"] == "application/pdf"

    # The client sends the bytes to the target WITHOUT its MCP credential.
    put = client.put(target["url"], content=content,
                     headers={**target["headers"], "Authorization": ""})
    assert put.status_code == 204

    # ... then repeats the call with the same arguments and the state.
    retry = modern_call(
        client, "tools/call",
        {"name": "probe_file", "arguments": args, "requestState": first["requestState"]},
        caps=UPLOAD_CAPS, req_id=2)
    body = report(retry)
    assert body["probe"] == "ok" and body["transfer"] == "out-of-band"
    assert body["file"]["receivedBytes"] == 1000
    assert body["file"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert body["request"]["clientInfo"] == {"name": "pytest", "version": "1"}

    # The staged file is gone and the state cannot be used a second time.
    assert list((tmp_path / "staging").iterdir()) == []
    again = modern_call(
        client, "tools/call",
        {"name": "probe_file", "arguments": args, "requestState": first["requestState"]},
        caps=UPLOAD_CAPS, req_id=3).json()
    assert again["error"]["code"] == -32602


def test_metadata_only_without_upload_capability_is_a_capability_error(client):
    r = modern_call(client, "tools/call",
                    {"name": "probe_file", "arguments": {"file": file_arg(b"x" * 500)}})
    assert r.status_code == 400
    error = r.json()["error"]
    assert error["code"] == -32021
    assert error["data"]["requiredCapabilities"] == UPLOAD_CAPS


def test_retry_with_changed_arguments_is_rejected(client):
    content = b"y" * 500
    first = modern_call(client, "tools/call",
                        {"name": "probe_file", "arguments": {"file": file_arg(content)}},
                        caps=UPLOAD_CAPS).json()["result"]
    target = first["uploads"][0]
    client.put(target["url"], content=content, headers=target["headers"])

    changed = {"file": file_arg(content, name="other.pdf")}
    r = modern_call(client, "tools/call",
                    {"name": "probe_file", "arguments": changed,
                     "requestState": first["requestState"]}, caps=UPLOAD_CAPS).json()
    assert r["error"]["code"] == -32602


def test_retry_without_upload_fails_without_running(client):
    first = modern_call(client, "tools/call",
                        {"name": "probe_file", "arguments": {"file": file_arg(b"z" * 500)}},
                        caps=UPLOAD_CAPS).json()["result"]
    r = modern_call(client, "tools/call",
                    {"name": "probe_file", "arguments": {"file": file_arg(b"z" * 500)},
                     "requestState": first["requestState"]}, caps=UPLOAD_CAPS)
    assert r.json()["result"]["isError"] is True
    assert "no bytes arrived" in report(r)["reason"]


def test_upload_target_checks_token_size_and_single_use(client):
    content = b"a" * 500
    first = modern_call(client, "tools/call",
                        {"name": "probe_file", "arguments": {"file": file_arg(content)}},
                        caps=UPLOAD_CAPS).json()["result"]
    target = first["uploads"][0]

    wrong = {**target["headers"], file_probe.UPLOAD_TOKEN_HEADER: "nope"}
    assert client.put(target["url"], content=content, headers=wrong).status_code == 403
    # Too many bytes: refused, and the target is spent.
    assert client.put(target["url"], content=content + b"!",
                      headers=target["headers"]).status_code == 413
    assert client.put(target["url"], content=content,
                      headers=target["headers"]).status_code == 403


def test_oversized_and_malformed_files_are_tool_errors(client):
    too_big = {"id": "f", "mimeType": "application/pdf", "size": 5000}
    r = modern_call(client, "tools/call",
                    {"name": "probe_file", "arguments": {"file": too_big}}, caps=UPLOAD_CAPS)
    assert r.json()["result"]["isError"] is True

    lying = file_arg(b"abc", inline=True)
    lying["size"] = 99
    r = modern_call(client, "tools/call", {"name": "probe_file", "arguments": {"file": lying}})
    assert r.json()["result"]["isError"] is True

    r = modern_call(client, "tools/call", {"name": "probe_file", "arguments": {}})
    assert r.json()["result"]["isError"] is True


def test_digest_is_verified_when_sent(client):
    content = b"digest me"
    good = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
    ok = file_arg(content, inline=True, digest={"algorithm": "sha-256", "value": good})
    r = modern_call(client, "tools/call", {"name": "probe_file", "arguments": {"file": ok}})
    assert report(r)["probe"] == "ok"

    bad = file_arg(content, inline=True, digest={"algorithm": "sha-256", "value": "AAAA"})
    r = modern_call(client, "tools/call", {"name": "probe_file", "arguments": {"file": bad}})
    assert r.json()["result"]["isError"] is True


def test_modern_header_validation(client):
    r = modern_call(client, "tools/list", headers={"MCP-Protocol-Version": "2025-11-25"})
    assert r.status_code == 400 and r.json()["error"]["code"] == -32020

    r = modern_call(client, "tools/list", headers={"Mcp-Method": "tools/call"})
    assert r.status_code == 400 and r.json()["error"]["code"] == -32020

    r = modern_call(client, "tools/call", {"name": "probe_status"},
                    headers={"Mcp-Name": "probe_file"})
    assert r.status_code == 400 and r.json()["error"]["code"] == -32020

    r = modern_call(client, "no/such-method")
    assert r.status_code == 404 and r.json()["error"]["code"] == -32601


def test_unsupported_modern_version_lists_supported_ones(client):
    r = client.post(
        "/mcp-probe",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": {
            "io.modelcontextprotocol/protocolVersion": "2099-01-01",
            "io.modelcontextprotocol/clientCapabilities": {}}}},
        headers={"MCP-Protocol-Version": "2099-01-01", "Mcp-Method": "tools/list"})
    assert r.status_code == 400
    error = r.json()["error"]
    assert error["code"] == -32022 and MODERN in error["data"]["supported"]


# --- Legacy era ---------------------------------------------------------------

def legacy_call(client, method, params=None, req_id=1):
    return client.post(
        "/mcp-probe",
        json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}},
        headers={"MCP-Protocol-Version": "2025-11-25"})


def test_legacy_handshake_and_tools(client):
    init = client.post("/mcp-probe", json={
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "old-client", "version": "1"}}}).json()["result"]
    assert init["protocolVersion"] == "2025-11-25"
    assert "resultType" not in init  # legacy results carry no resultType

    note = client.post("/mcp-probe", json={"jsonrpc": "2.0",
                                           "method": "notifications/initialized"})
    assert note.status_code == 202

    tools = legacy_call(client, "tools/list").json()["result"]["tools"]
    assert [t["name"] for t in tools] == ["probe_file", "probe_status"]
    assert client.get("/mcp-probe").status_code == 405


def test_legacy_client_gets_an_explanation_instead_of_an_upload(client):
    r = legacy_call(client, "tools/call",
                    {"name": "probe_file", "arguments": {"file": file_arg(b"q" * 500)}})
    result = r.json()["result"]
    assert result["isError"] is True
    assert "2026-07-28" in report(r)["reason"]


def test_status_shows_what_the_client_declared_and_no_secrets(client):
    content = b"s" * 500
    first = modern_call(client, "tools/call",
                        {"name": "probe_file", "arguments": {"file": file_arg(content)}},
                        caps=UPLOAD_CAPS).json()["result"]
    target = first["uploads"][0]
    client.put(target["url"], content=content, headers=target["headers"])

    r = modern_call(client, "tools/call", {"name": "probe_status"}, caps=UPLOAD_CAPS)
    text = r.json()["result"]["content"][0]["text"]
    status = json.loads(text)
    assert status["thisRequest"]["clientCapabilities"] == UPLOAD_CAPS
    events = [e["event"] for e in status["recent"]]
    assert "probe_file" in events and "upload" in events
    # Neither the upload token nor the request state may leak into the status.
    assert target["headers"][file_probe.UPLOAD_TOKEN_HEADER] not in text
    assert first["requestState"] not in text


def test_probe_is_absent_unless_enabled():
    code = ("import os, auth_gateway;"
            "print([r.path for r in auth_gateway.routes if 'probe' in r.path])")
    import subprocess
    env = {**os.environ, "FILE_PROBE_ENABLED": ""}
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,
                         text=True, cwd=Path(__file__).resolve().parent.parent)
    assert out.stdout.strip() == "[]", out.stderr
