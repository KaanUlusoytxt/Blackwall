# Blackwall MCP Server

[`mcp_server.py`](mcp_server.py) exposes Blackwall's tools over the
[Model Context Protocol](https://modelcontextprotocol.io/) so that MCP clients
such as **Claude Desktop** can drive Blackwall with tool calls.

The MCP server is a thin client: it talks to a **running** Blackwall instance's
HTTP API (default `http://127.0.0.1:8000`). It does **not** modify or embed
Blackwall — start Blackwall separately (`python app.py` or `./run.sh`).

```
Claude Desktop ──(MCP/stdio)──▶ mcp_server.py ──(HTTP)──▶ Blackwall API (127.0.0.1:8000)
```

## Install

The MCP SDK ships in `requirements.txt`:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Security — read this first

`send_request` and `run_intruder` actually send traffic to a target. To prevent
accidentally attacking the wrong host, they are gated by an allow-list:

- Set **`BLACKWALL_ALLOWED_HOSTS`** to a comma/space-separated list of allowed
  target hosts. Wildcards like `*.web-security-academy.net` are supported.
- If the variable is **empty or unset, both tools refuse every target** and tell
  you to configure it.
- The read-only / offline tools (`get_history`, `get_flow`, `decode`,
  `jwt_decode`, `jwt_sign`, `check_oast`) are not gated.

Example:

```bash
export BLACKWALL_ALLOWED_HOSTS="0a1b00.web-security-academy.net, *.web-security-academy.net"
```

## Tools

| Tool | What it does |
|------|--------------|
| `get_history` | List captured requests from the proxy history (filterable). |
| `get_flow` | Full request + response of one history entry by id. |
| `send_request` | Send one request (Repeater) and return the response. **Allow-listed.** |
| `run_intruder` | Fuzz a `§...§`-marked request with payload sets (sniper/pitchfork/cluster) + optional grep; returns the result table. **Allow-listed.** |
| `decode` | Multi-layer encode/decode/hash pipeline (base64, url, html, hex, ascii, md5/sha…). |
| `jwt_decode` | Decode a JWT (header/payload/alg/signature), no verification. |
| `jwt_sign` | Forge/sign a JWT (`alg:none` or HS256 with a secret). |
| `check_oast` | Status + captured out-of-band (interactsh) interactions. |

(Raw sender and Race are intentionally not exposed yet.)

## Connect Claude Desktop

1. Make sure Blackwall is running (`python app.py` or `./run.sh`).
2. Find the two absolute paths you'll need:

   ```bash
   # from the project root:
   echo "$PWD/.venv/bin/python"
   echo "$PWD/mcp_server.py"
   ```

3. Open Claude Desktop's config file:
   - **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Linux:** `~/.config/Claude/claude_desktop_config.json`
   - **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

4. Add a `blackwall` server entry (use the absolute paths from step 2):

   ```json
   {
     "mcpServers": {
       "blackwall": {
         "command": "/ABSOLUTE/PATH/TO/Blackwall/.venv/bin/python",
         "args": ["/ABSOLUTE/PATH/TO/Blackwall/mcp_server.py"],
         "env": {
           "BLACKWALL_URL": "http://127.0.0.1:8000",
           "BLACKWALL_ALLOWED_HOSTS": "*.web-security-academy.net"
         }
       }
     }
   }
   ```

   On Windows use the venv path `...\\.venv\\Scripts\\python.exe` and escape
   backslashes in JSON.

5. Restart Claude Desktop. You should see the **blackwall** tools available. Try:
   *"List the last 10 requests in Blackwall's history"* → `get_history`.

## Use with any MCP client / quick check

The server speaks MCP over stdio:

```bash
BLACKWALL_ALLOWED_HOSTS="*.web-security-academy.net" .venv/bin/python mcp_server.py
```

Or inspect it with the MCP Inspector:

```bash
npx @modelcontextprotocol/inspector .venv/bin/python mcp_server.py
```

## Troubleshooting

- **"Blackwall is not running"** — start Blackwall first; check `BLACKWALL_URL`.
- **"No allowed hosts configured"** — set `BLACKWALL_ALLOWED_HOSTS`.
- **"Host not in the allow-list"** — add the target host to `BLACKWALL_ALLOWED_HOSTS`.
