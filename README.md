# Basic Memory Uberspace

Run your own [Basic Memory](https://basicmemory.com) MCP server on
[Uberspace 8](https://uberspace.de) and connect it to OAuth-capable AI clients
(Claude.ai, ChatGPT Developer Mode, and any client that speaks the MCP
authorization spec).

Basic Memory's HTTP transport ships **without authentication** — it is meant to
sit behind your own auth layer. This project provides that layer: a tiny,
single-file **OAuth 2.1 gateway** that you put in front of Basic Memory. It
handles the full authorization-code + PKCE flow with a fixed client ID/secret
and a single password login, then transparently reverse-proxies authenticated
requests (including SSE streaming) to your local Basic Memory instance.

```
Web client ── HTTPS ──> https://<user>.uber.space/mcp
                              │  (Caddy → web backend)
                              ▼
                        auth_gateway.py        ← OAuth 2.1 + PKCE, token check
                              │  127.0.0.1
                              ▼
                        basic-memory           ← MCP server, streamable-http
                          (127.0.0.1:8000)        no auth, localhost only
```

## Why this exists

- **Single user, self-hosted, no public cloud IdP.** No Google/GitHub login, no
  Logto/Auth0, no Keycloak, no Docker. Everything runs as plain user services on
  Uberspace.
- **Works with browser-based AI clients.** Claude.ai and ChatGPT require OAuth
  (a static bearer token is not enough); this gateway speaks the OAuth flow they
  expect, using a client ID/secret you define yourself.
- **Minimal.** One Python file, configuration via `.env`, dependencies managed
  with [uv](https://docs.astral.sh/uv/).

## What you get

- OAuth 2.1 authorization-code flow with mandatory **PKCE (S256)**
- Fixed, self-chosen **client ID / client secret** (no dynamic client registration)
- A single **password login** page for the `/authorize` step
- JWT access tokens + rotating refresh tokens
- RFC 8414 / RFC 9728 discovery documents so clients can auto-configure
- Token-validated **reverse proxy** to Basic Memory with SSE/streaming pass-through

---

## Requirements

- An Uberspace 8 account (referred to as user `ubernaut` below — replace with
  your own username throughout)
- SSH access to your Uberspace
- `uv` and `basic-memory` (installed in the steps below)

---

## Installation from scratch

All commands run on your Uberspace shell unless noted otherwise. Replace
`ubernaut` with your actual username everywhere.

### 1. Install uv

`uv` manages Python versions, virtual environments, and dependencies.

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc
uv --version
```

### 2. Install and initialize Basic Memory

```bash
uv tool install basic-memory
basic-memory sync          # initializes ~/.basic-memory and indexes your notes
basic-memory --version     # sanity check
```

Your notes live as Markdown files under `~/basic-memory` by default.

### 3. Get this project

```bash
git clone https://github.com/yeah/basic-memory-uberspace.git ~/auth_gateway
cd ~/auth_gateway
uv sync                    # installs gateway dependencies into .venv, writes uv.lock
```

### 4. Create your configuration

```bash
cp .env.example .env
```

Generate two strong secrets:

```bash
openssl rand -hex 32       # use for CLIENT_SECRET
openssl rand -hex 32       # use for JWT_SECRET
```

Edit `.env` and set:

```ini
BASE_URL=https://ubernaut.uber.space
PORT=8001
UPSTREAM_URL=http://127.0.0.1:8000
CLIENT_ID=basic-memory
CLIENT_SECRET=<first openssl value>
JWT_SECRET=<second openssl value>
LOGIN_PASSWORD=<a password you choose>
```

Protect the file (it contains secrets):

```bash
chmod 600 .env
```

> **Important:** `BASE_URL` must exactly match the public URL of your Uberspace,
> without the `/mcp` suffix. If it is wrong, the OAuth discovery breaks for
> browser clients.

### 5. Create the two services

Uberspace 8 uses systemd user services. We run **two**: Basic Memory (local
only) and the gateway (public).

**Basic Memory** — bound to localhost, never exposed directly:

```bash
uberspace service add basicmemory \
  "$HOME/.local/bin/basic-memory mcp --transport streamable-http --host 127.0.0.1 --port 8000"
```

**The gateway** — runs via uv. First find your uv path:

```bash
which uv
```

Then create the service. Note Uberspace's `service add` may not pass a working
directory or `.env` reliably through its command string, so we set the working
directory directly in the unit file afterwards.

```bash
uberspace service add authgw "$(which uv) run python $HOME/auth_gateway/auth_gateway.py"
```

Now edit the unit to add the working directory (so uv finds `pyproject.toml`
and the gateway finds `.env`):

```bash
nano ~/.config/systemd/user/authgw.service
```

Make the `[Service]` section look like this (keep your real uv path in
`ExecStart`):

```ini
[Service]
WorkingDirectory=/home/ubernaut/auth_gateway
ExecStart=/home/ubernaut/.local/bin/uv run python auth_gateway.py
```

Reload and (re)start:

```bash
systemctl --user daemon-reload
systemctl --user restart authgw
systemctl --user status authgw --no-pager        # should be active (running)
systemctl --user status basicmemory --no-pager   # should be active (running)
```

If the gateway logs `WARNING: ... is not set`, your `.env` is not being read —
check `WorkingDirectory` and that `.env` exists in it.

### 6. Wire up the web backend

Route **all** traffic on `/` to the gateway. The gateway itself forwards `/mcp`
to Basic Memory after checking the token. Do **not** add a separate `/mcp`
backend pointing at port 8000 — that would bypass authentication.

```bash
uberspace web backend set / --http --port 8001
uberspace web backend list
```

> On some Uberspace 8 versions the subcommand is `add` instead of `set`:
> `uberspace web backend add / port 8001` (use `--force` if `/` already exists).
> The list should show only `/ → 8001`.

### 7. Verify the whole chain

Discovery documents must show your real domain (not `127.0.0.1`):

```bash
curl -s https://ubernaut.uber.space/.well-known/oauth-protected-resource | python3 -m json.tool
curl -s https://ubernaut.uber.space/.well-known/oauth-authorization-server | python3 -m json.tool
```

Unauthenticated request must be rejected:

```bash
curl -si https://ubernaut.uber.space/mcp -X POST | head -3   # expect HTTP/2 401
```

Authenticated request must reach Basic Memory. Issue a test token using your
configured secrets, then call `initialize`:

```bash
cd ~/auth_gateway
TOKEN=$(uv run python -c "from auth_gateway import _issue_access_token; print(_issue_access_token())")

curl -si https://ubernaut.uber.space/mcp \
  -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
```

Expected: `HTTP/2 200`, `content-type: text/event-stream`, and an
`initialize` result containing `"serverInfo":{"name":"Basic Memory",...}`.

---

## Connecting clients

### Claude.ai

1. Settings → Connectors → **Add custom connector**
2. **URL:** `https://ubernaut.uber.space/mcp`
3. **Advanced settings:**
   - **OAuth Client ID:** the `CLIENT_ID` from your `.env` (e.g. `basic-memory`)
   - **OAuth Client Secret:** the `CLIENT_SECRET` from your `.env`
4. **Connect** → your login page opens in the browser → enter `LOGIN_PASSWORD`.
5. Enable the connector in a chat and try: *"search my notes about …"*

### ChatGPT (Developer Mode)

Settings → Apps & Connectors → Advanced → enable **Developer Mode**, then create
a connector pointing at the same URL with the same client ID/secret. ChatGPT is
stricter about discovery and may expect refresh handling; this gateway issues
refresh tokens, so it should complete the flow.

### Other clients

Clients that accept a static bearer token (e.g. Mistral Le Chat, Gemini CLI,
Cursor) can also use the gateway — point them at `https://ubernaut.uber.space/mcp`
and let them run the OAuth flow, or supply a token issued by the gateway.

---

## Configuration reference

| Variable            | Required | Default                     | Description |
|---------------------|----------|-----------------------------|-------------|
| `BASE_URL`          | yes      | `https://ubernaut.uber.space` | Public URL of the gateway, without `/mcp`. Sets the OAuth issuer and token audience. |
| `PORT`              | no       | `8001`                      | Port the gateway listens on. |
| `UPSTREAM_URL`      | no       | `http://127.0.0.1:8000`     | Local Basic Memory MCP server. |
| `CLIENT_ID`         | yes      | `basic-memory`              | Fixed OAuth client ID. |
| `CLIENT_SECRET`     | yes      | —                           | Fixed OAuth client secret. |
| `JWT_SECRET`        | yes      | —                           | Signing key for access tokens. Keep stable. |
| `LOGIN_PASSWORD`    | yes      | —                           | Password for the `/authorize` login page. |
| `ACCESS_TOKEN_TTL`  | no       | `3600`                      | Access-token lifetime (seconds). |
| `REFRESH_TOKEN_TTL` | no       | `2592000`                   | Refresh-token lifetime (seconds). |
| `AUTH_CODE_TTL`     | no       | `300`                       | Authorization-code lifetime (seconds). |

---

## Operating notes

- **Updating dependencies:** `uv add <pkg>` / `uv remove <pkg>` updates
  `pyproject.toml` and `uv.lock`. Re-deploy with `uv sync`.
- **Restarts and re-login:** access tokens are verified purely via `JWT_SECRET`,
  so they survive a gateway restart. Refresh tokens are kept in memory and are
  lost on restart — clients re-authenticate the next time a refresh is needed.
  For a single user this is usually fine. To avoid it entirely, persist refresh
  tokens (e.g. in SQLite); not implemented here to keep the gateway minimal.
- **Forcing a fresh OAuth flow** (e.g. for testing): change `JWT_SECRET` and
  restart, or remove and re-add the connector in the client.
- **Logs:** `journalctl --user -u authgw -n 50 --no-pager`

## Security notes

- This is a **single-user** design. The `/authorize` page is protected by one
  password; there is no user management.
- All traffic is HTTPS-terminated by Uberspace's Caddy. Basic Memory itself is
  bound to `127.0.0.1` and is never reachable from the internet directly.
- The gateway implements its own OAuth endpoints. Review the code before relying
  on it for anything beyond personal use.

## License

MIT — see [LICENSE](LICENSE).
