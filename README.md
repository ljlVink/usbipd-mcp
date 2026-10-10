# usbipd HTTP MCP

A Python Streamable HTTP MCP service running as a Windows administrator process, letting agents inside WSL call the Windows `usbipd` tool.

## Requirements

- Windows, administrator terminal; Python 3.12+.
- `usbipd-win` 5.x with `usbipd.exe` on PATH.
- WSL 2 and a working distribution. Keep at least one WSL distribution running before attaching.
- [uv](https://docs.astral.sh/uv/) recommended; the project ships a `uv.lock`.

## Startup

In an **administrator PowerShell** in the project directory:

```powershell
uv sync --locked
powershell -NoProfile -ExecutionPolicy Bypass -File .\start.ps1
```

To specify the address and port explicitly:

```powershell
.\start.ps1 -ListenAddress 172.25.112.1 -Port 8765
```

Without uv:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
powershell -NoProfile -ExecutionPolicy Bypass -File .\start.ps1
```

You can also run it directly; the token is read from an environment variable or a file:

```powershell
.\.venv\Scripts\python.exe server.py --host 172.25.112.1 --port 8765 --timeout 90
```

## Token and Security Boundary

The first run of the startup script generates a 32-byte random token, saves it as `.usbipd-mcp-token` inside the project, and reuses it from then on.

Every HTTP request must carry:

```text
Authorization: Bearer <actual token>
```

## Connecting a WSL agent

### NAT mode

Inside WSL, the Windows address is usually the gateway of the default route:

```bash
export WINDOWS_HOST="$(ip -4 route show default | cut -d ' ' -f 3)"
export USBIPD_MCP_URL="http://${WINDOWS_HOST}:8765/mcp"
export USBIPD_MCP_TOKEN="$(cat /mnt/c/Users/16662/Desktop/Projects/usbipd_server/.usbipd-mcp-token)"
```

Update the token path after moving the project. Only agents started from that shell inherit the environment variables. Do not commit the token to a config repo or paste it into chat logs.

### Mirrored mode

Start with `start.ps1 -ListenAddress 127.0.0.1`, point the client URL at `http://127.0.0.1:8765/mcp`

### Codex configuration

Add to WSL's `~/.codex/config.toml` (use the actual service output for the NAT address):

```toml
[mcp_servers.usbipd]
url = "http://172.25.112.1:8765/mcp"
bearer_token_env_var = "USBIPD_MCP_TOKEN"
startup_timeout_sec = 15
tool_timeout_sec = 120
```

Set the `USBIPD_MCP_TOKEN` above before starting. This is not a `command`/stdio server, so the agent does not need to launch a Windows administrator process.
