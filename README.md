# Basic Memory Uberspace

Run your own [Basic Memory](https://basicmemory.com) MCP server on
[Uberspace 8](https://uberspace.de) and expose it through a single, auditable
Python entrypoint that serves:

- **`/mcp`** — the MCP server, protected by **OAuth 2.1 + PKCE**, for AI clients
  (Claude.ai, ChatGPT Developer Mode, …).
- **`/dav`** — a **WebDAV** view of the same notes, protected by **Basic Auth**,
  for editors like [Obsidian](https://obsidian.md) on macOS and iOS.

Both share **one set of credentials** from a single `.env`: the OAuth client ID
doubles as the WebDAV username, and one password covers both the OAuth login and
WebDAV Basic Auth.

```
                          ┌────────────────────────────────────┐
Claude / ChatGPT ─OAuth──▶│                                         │──▶ Basic Memory (8000)
                          │   auth_gateway.py  (single entrypoint)   │
Obsidian ────────Basic───▶│   /mcp  → OAuth  → proxy                 │──▶ WsgiDAV (8002)
                          │   /dav  → Basic  → proxy                 │      → ~/basic-memory
                          │   /.well-known, /authorize, /token       │
                          └─────────────────────────────────────────┘
```

All three processes run as plain systemd user services. Basic Memory and WsgiDAV
bind `127.0.0.1` (private to your Uberspace's network namespace) and are only
reachable through the gateway, which is the sole public entrypoint.

## Why this exists

- **Single user, self-hosted, no public cloud IdP.** No Google/GitHub login, no
  Logto/Auth0, no Keycloak, no Docker.
- **Works with browser-based AI clients.** Claude.ai and ChatGPT require OAuth;
  this gateway speaks the flow they expect with a client ID/secret you define.
- **Works with Obsidian** (macOS + iOS) via WebDAV sync, against the very same
  Markdown files Basic Memory uses.
- **One auditable entrypoint.** A single Python file terminates all auth; the
  upstreams have no auth of their own and never face the internet.
- **Minimal.** One gateway file, configuration via `.env`, dependencies managed
  with [uv](https://docs.astral.sh/uv/).

---

## Requirements

- An Uberspace 8 account (referred to as user `ubernaut` below — replace with
  your own username throughout)
- SSH access to your Uberspace

`uv` is already installed on Uberspace 8 (at `/usr/bin/uv`), so there is nothing
to install for the Python toolchain.

---

## Installation from scratch

All commands run on your Uberspace shell unless noted otherwise. Replace
`ubernaut` with your actual username everywhere.

### 1. Get this project

```bash
git clone https://github.com/yeah/basic-memory-uberspace.git ~/auth_gateway
cd ~/auth_gateway
uv sync                    # installs everything (incl. Basic Memory) from uv.lock
```

`uv sync` installs all dependencies — the gateway, WsgiDAV, **and Basic Memory
itself** — at the exact versions pinned in `uv.lock`. Nothing else to install
by hand. Your notes will live as Markdown files under `~/basic-memory` by
default.

### 2. Create your configuration

```bash
cp .env.example .env
```

Generate two strong secrets:

```bash
openssl rand -hex 32       # use for CLIENT_SECRET
openssl rand -hex 32       # use for JWT_SECRET
```

Edit `.env` and set at least:

```ini
BASE_URL=https://ubernaut.uber.space
CLIENT_ID=basic-memory
CLIENT_SECRET=<first openssl value>
JWT_SECRET=<second openssl value>
LOGIN_PASSWORD=<a password you choose>
```

`LOGIN_PASSWORD` is used both for the OAuth browser login and as the WebDAV
password. The WebDAV username defaults to `CLIENT_ID`.

Protect the file (it contains secrets):

```bash
chmod 600 .env
```

> **Important:** `BASE_URL` must exactly match the public URL of your Uberspace,
> without the `/mcp` suffix. If it is wrong, the OAuth discovery breaks for
> browser clients.

### 3. Point WsgiDAV at your notes

Edit `wsgidav.yaml` and set the `provider_mapping` to the absolute path of your
notes (WsgiDAV does not expand `~`):

```yaml
provider_mapping:
  "/dav": "/home/ubernaut/basic-memory"
```

Leave `simple_dc` on anonymous access — the gateway is the gatekeeper, WsgiDAV
only ever listens on `127.0.0.1`.

### 4. Create the three services

Uberspace 8 uses systemd user services. We run **three**, all started with
`--workdir` so uv finds the project and the gateway finds `.env`.

**Basic Memory** — MCP server on `127.0.0.1:8000`:

```bash
uberspace service add basicmemory \
  "/usr/bin/uv run basic-memory mcp --transport streamable-http --host 127.0.0.1 --port 8000" \
  --workdir "$HOME/auth_gateway"
```

**WsgiDAV** — WebDAV server on `127.0.0.1:8002`:

```bash
uberspace service add wsgidav \
  "/usr/bin/uv run wsgidav --config wsgidav.yaml" \
  --workdir "$HOME/auth_gateway"
```

**The gateway** — the single public entrypoint, binds `0.0.0.0:8001`:

```bash
uberspace service add auth_gateway \
  "/usr/bin/uv run python auth_gateway.py" \
  --workdir "$HOME/auth_gateway"
```

> The gateway must bind `0.0.0.0` because that is what the web backend connects
> to. Basic Memory and WsgiDAV stay on `127.0.0.1`: each Uberspace lives in its
> own network namespace with its own loopback, so `127.0.0.1` is private to your
> account and unreachable by other users on the host.

Check all three:

```bash
systemctl --user status auth_gateway --no-pager
systemctl --user status basicmemory  --no-pager
systemctl --user status wsgidav      --no-pager
```

If the gateway logs `ModuleNotFoundError` or `WARNING: ... is not set`, the
working directory is wrong — verify `--workdir` points at the cloned repo and
that `.env` exists there.

### 5. Wire up the web backends

Map only the specific gateway paths, so `/` stays free for other uses. The
gateway forwards `/mcp` to Basic Memory and `/dav` to WsgiDAV after checking
auth; never point a backend straight at port 8000 or 8002.

```bash
uberspace web backend del /          # remove the default Apache backend on these paths if present
uberspace web backend add /mcp port 8001
uberspace web backend add /dav port 8001
uberspace web backend add /authorize port 8001
uberspace web backend add /token port 8001
uberspace web backend add /.well-known/oauth-protected-resource port 8001
uberspace web backend add /.well-known/oauth-authorization-server port 8001
uberspace web backend add /favicon.ico port 8001
uberspace web backend list
```

> `/` itself is no longer routed to the gateway, leaving it available for
> anything else you host on this Uberspace.
>
> The `/favicon.ico` mapping is optional. The gateway answers it with a 302
> redirect to the Basic Memory logo on basicmemory.com, so favicon services
> (such as the one Claude uses to show a connector icon) find an icon for the
> domain. Note that these services cache per-domain for a long time, so any
> change may take a while to appear.

---

## Connecting clients

### Claude.ai (MCP over OAuth)

1. Settings → Connectors → **Add custom connector**
2. **URL:** `https://ubernaut.uber.space/mcp`
3. **Advanced settings:**
   - **OAuth Client ID:** your `CLIENT_ID` (e.g. `basic-memory`)
   - **OAuth Client Secret:** your `CLIENT_SECRET`
4. **Connect** → the login page opens in the browser → enter `LOGIN_PASSWORD`.
5. Enable the connector in a chat and try: *"search my notes about …"*

### ChatGPT (Developer Mode)

Settings → Apps & Connectors → Advanced → enable **Developer Mode**, then add a
connector pointing at the same URL with the same client ID/secret. The gateway
issues refresh tokens, so the flow completes.

### Obsidian (WebDAV sync, macOS + iOS)

Obsidian works on a local vault and syncs it to the WebDAV endpoint with a
community plugin. Use [Obsidian WebDAV Sync](https://github.com/hesprs/obsidian-webdav-sync)
by hesprs (an actively maintained alternative to the unmaintained Remotely Save).

On **each** device (macOS and iOS):

1. Community plugins → turn off Restricted Mode → Browse → install **WebDAV Sync**
   (hesprs) → enable it.
2. Plugin settings:
   - **Server address:** `https://ubernaut.uber.space/dav`
   - **Username:** your `CLIENT_ID` (e.g. `basic-memory`)
   - **Password:** your `LOGIN_PASSWORD`
3. **Exclude `.obsidian` from sync** in the plugin's ignore settings. It holds
   per-device Obsidian config that should not travel between devices and is not
   part of your Basic Memory notes.

**Two-writer note:** Basic Memory and Obsidian both write into `~/basic-memory`.
The plugin's three-way merge handles this well, but to be safe start with manual
or on-startup sync (not real-time) and avoid editing the same file in Obsidian
while Basic Memory is actively writing it.

---

## Configuration reference

| Variable            | Required | Default                     | Description |
|---------------------|----------|-----------------------------|-------------|
| `BASE_URL`          | yes      | `https://ubernaut.uber.space` | Public URL of the gateway, without `/mcp`. Sets the OAuth issuer and token audience. |
| `PORT`              | no       | `8001`                      | Port the gateway listens on. |
| `UPSTREAM_URL`      | no       | `http://127.0.0.1:8000`     | Local Basic Memory MCP server. |
| `DAV_UPSTREAM_URL`  | no       | `http://127.0.0.1:8002`     | Local WsgiDAV WebDAV server. |
| `CLIENT_ID`         | yes      | `basic-memory`              | Fixed OAuth client ID; also the WebDAV username. |
| `CLIENT_SECRET`     | yes      | —                           | Fixed OAuth client secret. |
| `JWT_SECRET`        | yes      | —                           | Signing key for access tokens. Keep stable. |
| `LOGIN_PASSWORD`    | yes      | —                           | Password for both OAuth login and WebDAV Basic Auth. |
| `WEBDAV_USERNAME`   | no       | value of `CLIENT_ID`        | Override the WebDAV username if you want it to differ from the OAuth client ID. |
| `LOGO_URI`          | no       | Basic Memory logo on basicmemory.com | Logo shown on the login page, in resource metadata, and as the /favicon.ico redirect target. |
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
- **Forcing a fresh OAuth flow** (e.g. for testing): change `JWT_SECRET` and
  restart, or remove and re-add the connector in the client.
- **Logs:** `journalctl --user -u auth_gateway -n 50 --no-pager` (likewise for
  `basicmemory` and `wsgidav`).

## Security notes

- This is a **single-user** design. There is no user management; one password
  guards both the OAuth login and WebDAV.
- The gateway is the only public entrypoint. Basic Memory and WsgiDAV bind
  `127.0.0.1` inside your Uberspace's private network namespace and are never
  reachable from the internet directly. All external traffic is HTTPS-terminated
  by Uberspace's web backend in front of the gateway.
- The gateway implements its own OAuth and Basic Auth. Review the code before
  relying on it for anything beyond personal use.

## License

MIT — see [LICENSE](LICENSE).
