# Basic Memory OAuth Server

Run your own [Basic Memory](https://basicmemory.com) MCP server behind a single,
auditable Python entrypoint that adds authentication and exposes:

- **`/mcp`** — the MCP server, protected by **OAuth 2.1 + PKCE**, for AI clients
  (Claude.ai, ChatGPT Developer Mode, Mistral, …).
- **`/dav`** — a **WebDAV** view of the same notes, protected by **Basic Auth**,
  for editors like [Obsidian](https://obsidian.md) on macOS and iOS.

Both share **one set of credentials** from a single `.env`: the OAuth client ID
doubles as the WebDAV username, and one password covers both the OAuth login and
WebDAV Basic Auth.

```
                          ┌─────────────────────────────────────────┐
Claude / ChatGPT ─OAuth──▶│                                         │──▶ Basic Memory (8000)
                          │   auth_gateway.py  (single entrypoint)   │
Obsidian ────────Basic───▶│   /mcp  → OAuth  → proxy                 │──▶ WsgiDAV (8002)
                          │   /dav  → Basic  → proxy                 │      → notes directory
                          │   /.well-known, /authorize, /token       │
                          └─────────────────────────────────────────┘
```

The gateway is the only public entrypoint. Basic Memory and WsgiDAV have no auth
of their own and are never exposed to the internet directly — they are reachable
only through the gateway.

## Deployment

Two equally supported ways to run the stack. Both serve the same endpoints and
read the same `.env` keys — pick whichever fits your host.

### Docker Compose — [DOCKER.md](DOCKER.md)

Self-contained: the three services plus [Caddy](https://caddyserver.com) for
automatic HTTPS, on any host with Docker and a domain.

```bash
git clone https://github.com/yeah/basic-memory-oauth-server.git
cd basic-memory-oauth-server
cp .env.docker.example .env     # set DOMAIN + secrets
docker compose up -d --build
```

### Linux user services, e.g. Uberspace — [UBERSPACE.md](UBERSPACE.md)

The three processes as systemd user services behind your platform's web server.
Written for [Uberspace 8](https://uberspace.de) (no root, no Docker), adaptable
to any host with per-user systemd.

```bash
git clone https://github.com/yeah/basic-memory-oauth-server.git ~/auth_gateway
cd ~/auth_gateway
uv sync                         # installs everything, incl. Basic Memory
cp .env.example .env            # set BASE_URL + secrets
```

## Why this exists

- **Single user, self-hosted, no public cloud IdP.** No Google/GitHub login, no
  Logto/Auth0, no Keycloak.
- **Works with browser-based AI clients.** Claude.ai, ChatGPT and Mistral
  require OAuth; this gateway speaks the flow they expect with a client
  ID/secret you define.
- **Works with Obsidian** (macOS + iOS) via WebDAV sync, against the very same
  Markdown files Basic Memory uses.
- **One auditable entrypoint.** A single Python file terminates all auth; the
  upstreams have no auth of their own and never face the internet.
- **Minimal.** One gateway file, configuration via `.env`, dependencies managed
  with [uv](https://docs.astral.sh/uv/).

---

## Connecting clients

These steps are the same for both deployments. Replace `https://YOUR_SERVER`
with your Uberspace URL (e.g. `https://ubernaut.uber.space`) or your Docker
host's domain (e.g. `https://memory.example.com`).

### Claude.ai (MCP over OAuth)

1. Settings → Connectors → **Add custom connector**
2. **URL:** `https://YOUR_SERVER/mcp`
3. **Advanced settings:**
   - **OAuth Client ID:** your `CLIENT_ID` (e.g. `basic-memory`)
   - **OAuth Client Secret:** your `CLIENT_SECRET`
4. **Connect** → the login page opens in the browser → enter `LOGIN_PASSWORD`.
5. Enable the connector in a chat and try: *"search my notes about …"*

Claude's redirect URI is `https://claude.ai/api/mcp/auth_callback`, covered by
the `claude.ai` entry in `ALLOWED_REDIRECT_HOSTS`.

### ChatGPT (Developer Mode)

Settings → Apps & Connectors → Advanced → enable **Developer Mode**, then add a
connector pointing at the same URL with the same client ID/secret. The gateway
issues refresh tokens, so the flow completes.

ChatGPT generates a per-connector redirect URI on `chatgpt.com` (for example
`https://chatgpt.com/connector/oauth/<id>`), covered by the `chatgpt.com` entry
in `ALLOWED_REDIRECT_HOSTS`.

### Mistral (Le Chat)

In Le Chat, open **Intelligence → Connectors** (you must be an admin), add a
custom MCP connector pointing at the same `/mcp` URL, and complete the OAuth
consent. Mistral's redirect URI is on `callback.mistral.ai`, covered by that
entry in `ALLOWED_REDIRECT_HOSTS`.

### Obsidian (WebDAV sync, macOS + iOS)

Obsidian works on a local vault and syncs it to the WebDAV endpoint with a
community plugin. Use [Obsidian WebDAV Sync](https://github.com/hesprs/obsidian-webdav-sync)
by hesprs (an actively maintained alternative to the unmaintained Remotely Save).

On **each** device (macOS and iOS):

1. Community plugins → turn off Restricted Mode → Browse → install **WebDAV Sync**
   (hesprs) → enable it.
2. Plugin settings:
   - **Server address:** `https://YOUR_SERVER/dav`
   - **Username:** your `CLIENT_ID` (e.g. `basic-memory`)
   - **Password:** your `LOGIN_PASSWORD`
3. **Exclude `.obsidian` from sync** in the plugin's ignore settings. It holds
   per-device Obsidian config that should not travel between devices and is not
   part of your Basic Memory notes.

**Two-writer note:** Basic Memory and Obsidian both write into the same notes
directory. The plugin's three-way merge handles this well, but to be safe start
with manual or on-startup sync (not real-time) and avoid editing the same file
in Obsidian while Basic Memory is actively writing it.

---

## Configuration reference

The gateway is configured through these `.env` keys. In the Docker deployment,
`BASE_URL`, `UPSTREAM_URL` and `DAV_UPSTREAM_URL` are set automatically by
Compose, so there you only provide `DOMAIN` and the secrets.

| Variable            | Required | Default                     | Description |
|---------------------|----------|-----------------------------|-------------|
| `BASE_URL`          | yes      | `https://ubernaut.uber.space` | Public URL of the gateway, without `/mcp`. Sets the OAuth issuer and token audience. |
| `PORT`              | no       | `8001`                      | Port the gateway listens on. |
| `UPSTREAM_URL`      | no       | `http://127.0.0.1:8000`     | Basic Memory MCP server. |
| `DAV_UPSTREAM_URL`  | no       | `http://127.0.0.1:8002`     | WsgiDAV WebDAV server. |
| `CLIENT_ID`         | yes      | `basic-memory`              | Fixed OAuth client ID; also the WebDAV username. |
| `CLIENT_SECRET`     | yes      | —                           | Fixed OAuth client secret. |
| `JWT_SECRET`        | yes      | —                           | Signing key for access tokens. Keep stable. |
| `LOGIN_PASSWORD`    | yes      | —                           | Password for both OAuth login and WebDAV Basic Auth. |
| `AUTH_FAIL_LIMIT`   | no       | `10`                        | Failed LOGIN_PASSWORD attempts (global, across `/authorize` and `/dav`) within `AUTH_FAIL_WINDOW` before further attempts get HTTP 429. `0` disables the throttle. |
| `AUTH_FAIL_WINDOW`  | no       | `300`                       | Sliding window (seconds) for `AUTH_FAIL_LIMIT`. |
| `ALLOWED_REDIRECT_HOSTS` | yes* | —                       | Comma-separated hosts; an `https` redirect URI whose host matches exactly is allowed (any path). *Either this or `ALLOWED_REDIRECT_URIS` must be set. |
| `ALLOWED_REDIRECT_URIS` | yes* | —                           | Comma-separated **exact** full-URI allowlist of OAuth redirect URIs. *Either this or `ALLOWED_REDIRECT_HOSTS` must be set. Rejected URIs are logged. |
| `WEBDAV_USERNAME`   | no       | value of `CLIENT_ID`        | Override the WebDAV username if you want it to differ from the OAuth client ID. |
| `ACCESS_TOKEN_TTL`  | no       | `3600`                      | Access-token lifetime (seconds). |
| `REFRESH_TOKEN_TTL` | no       | `2592000`                   | Refresh-token lifetime (seconds). |
| `AUTH_CODE_TTL`     | no       | `300`                       | Authorization-code lifetime (seconds). |
| `FILE_PROBE_ENABLED` | no      | off                         | Set to `1` to serve the diagnostic endpoint `/mcp-probe` (see [File upload probe](#file-upload-probe)). |
| `FILE_PROBE_MAX_BYTES` | no    | `26214400`                  | Largest file the probe accepts (bytes). |
| `FILE_PROBE_MAX_INLINE_BYTES` | no | `1048576`               | Largest file the probe accepts inline in the tool call (bytes). |
| `FILE_PROBE_TTL`    | no       | `600`                       | Lifetime of a probe upload target (seconds). |
| `FILE_PROBE_DIR`    | no       | `<tmp>/bm-file-probe`       | Where probe uploads wait until they are checked and deleted. |

---

## File upload probe

An optional, diagnostic MCP endpoint that answers one question: can your MCP
client hand a **file** (a PDF, an image) to a tool without the model writing
the bytes out as text? It implements the draft
[MCP file-uploads extension](https://github.com/modelcontextprotocol/experimental-ext-file-uploads)
(`x-mcp-file`, pinned to the draft of 2026-11-09). The draft is experimental
and may change, and which clients support it is not documented yet. That is
what the probe finds out.

Enable it with `FILE_PROBE_ENABLED=1`, restart the gateway, and add a second
custom connector with the URL `https://<your-domain>/mcp-probe` and the same
OAuth client ID and secret as the main connector. It offers two tools:

- `probe_file` takes one file argument. It reports how the file arrived
  (`inline`, `out-of-band` or not at all), its size and SHA-256, and then
  deletes it. Nothing is stored and the notes are never touched.
- `probe_status` shows what the server saw from the client: protocol version,
  client name, declared capabilities, and the outcome of recent calls. It works
  even if the client cannot use `probe_file`.

How to read the result of asking the assistant to "send this file to
`probe_file`":

| Result | Meaning |
|--------|---------|
| `transfer: out-of-band` or `inline`, with the correct size | The client supports the extension. A real upload tool can be built on it. |
| The assistant cannot attach the file, or writes base64 by hand | The client ignores `x-mcp-file`. `probe_status` shows whether it declared the extension at all. |
| An error about a missing capability or protocol version | The client speaks an older protocol revision. Out-of-band upload needs `2026-07-28` or later. |

The same events are printed to the gateway log with the prefix `file-probe:`.

The probe accepts the same access token as `/mcp`. Out-of-band uploads go to
`/mcp-probe/upload/<id>` and are authorized by a one-time token that only the
client receives. Turn the probe off again when you are done testing.

---

## Operating notes

- **Restarts and re-login:** access tokens are verified purely via `JWT_SECRET`,
  so they survive a gateway restart. Refresh tokens are kept in memory and are
  lost on restart — clients re-authenticate the next time a refresh is needed.
- **Forcing a fresh OAuth flow** (e.g. for testing): change `JWT_SECRET` and
  restart, or remove and re-add the connector in the client.
- **Logs, updates and day-to-day commands** are deployment-specific — see
  [DOCKER.md](DOCKER.md) or [UBERSPACE.md](UBERSPACE.md).

## Security notes

- This is a **single-user** design. There is no user management; one password
  guards both the OAuth login and WebDAV.
- The gateway is the only public entrypoint. In both deployments the upstreams
  (Basic Memory, WsgiDAV) are bound to a private interface — loopback inside
  your Uberspace's network namespace, or an internal Docker network with no
  outbound internet — and are never reachable directly. TLS is terminated in
  front of the gateway (Uberspace's web backend, or Caddy in the Docker setup).
- The gateway implements its own OAuth and Basic Auth. Review the code before
  relying on it for anything beyond personal use.
- A global brute-force throttle (`AUTH_FAIL_LIMIT` / `AUTH_FAIL_WINDOW`) slows
  password guessing against `/authorize` and `/dav`: too many failed attempts
  in the window return HTTP 429 until it cools down. It is global rather than
  per-IP because the real client IP is not trustworthy behind the reverse
  proxy. The trade-off is that someone actively guessing can also lock you out
  for the (short, self-expiring) window. It is **not** a substitute for a
  strong password — use a long, randomly generated `LOGIN_PASSWORD`.

## License

MIT — see [LICENSE](LICENSE).
