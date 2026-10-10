from __future__ import annotations

import argparse
import asyncio
import ctypes
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Annotated, Any
from uuid import UUID

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import Field, IPvAnyAddress
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send
import uvicorn


TOKEN_FILE = Path(__file__).with_name(".usbipd-mcp-token")
BusId = Annotated[str, Field(pattern=r"^[0-9]+-[0-9]+$", max_length=32)]
Distribution = Annotated[
    str, Field(min_length=1, max_length=256, pattern=r"^[^\x00-\x1f-][^\x00-\x1f]*$")
]
READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False)
MUTATING = ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False)


class BearerAuth:
    def __init__(self, app: ASGIApp, token: str) -> None:
        self.app = app
        self.token = token.encode("ascii")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            headers = [value for key, value in scope["headers"] if key.lower() == b"authorization"]
            parts = headers[0].split() if len(headers) == 1 else []
            if (
                len(parts) != 2
                or parts[0].lower() != b"bearer"
                or not hmac.compare_digest(parts[1], self.token)
            ):
                response = JSONResponse(
                    {"error": "Bearer token required"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer", "Cache-Control": "no-store"},
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


def is_admin() -> bool:
    return os.name == "nt" and bool(ctypes.windll.shell32.IsUserAnAdmin())


class Usbipd:
    def __init__(self, executable: str, wsl: str, timeout: float) -> None:
        self.executable = executable
        self.wsl = wsl
        self.timeout = timeout
        self.lock = asyncio.Lock()

    async def run(self, executable: str, *args: str, encoding: str = "utf-8-sig") -> dict[str, Any]:
        try:
            process = await asyncio.create_subprocess_exec(
                executable, *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except OSError as exc:
            raise ToolError(f"Cannot start {Path(executable).name}: {exc}") from exc
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), self.timeout)
        except (TimeoutError, asyncio.CancelledError) as exc:
            if process.returncode is None:
                killer = await asyncio.create_subprocess_exec(
                    str(Path(os.environ["SystemRoot"]) / "System32" / "taskkill.exe"),
                    "/PID", str(process.pid), "/T", "/F",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                await killer.wait()
                if process.returncode is None:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
            await process.communicate()
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise ToolError(
                f"{Path(executable).name} {' '.join(args)} timed out after {self.timeout:g}s. "
                "The device state may already have changed; call usbipd_list before deciding what to do."
            ) from exc
        result = {
            "command": [Path(executable).name, *args],
            "exit_code": process.returncode,
            "stdout": stdout.decode(encoding, errors="replace").strip(),
            "stderr": stderr.decode(encoding, errors="replace").strip(),
        }
        if process.returncode != 0:
            raise ToolError(json.dumps(result, ensure_ascii=False))
        return result

    async def state(self) -> dict[str, Any]:
        result = await self.run(self.executable, "state")
        try:
            state = json.loads(result["stdout"])
        except json.JSONDecodeError as exc:
            raise ToolError(f"usbipd state returned invalid JSON: {result['stdout']}") from exc
        if not isinstance(state, dict) or not isinstance(state.get("Devices"), list):
            raise ToolError("usbipd state has an unsupported schema (expected Devices array)")
        return state

    async def distributions(self) -> list[str]:
        result = await self.run(self.wsl, "--list", "--quiet", encoding="utf-16-le")
        return [line.strip().lstrip("\ufeff") for line in result["stdout"].splitlines() if line.strip()]

    async def device(self, busid: str) -> dict[str, Any]:
        state = await self.state()
        for device in state["Devices"]:
            if device.get("BusId") == busid:
                return device
        raise ToolError(f"USB device {busid} is not connected. Call usbipd_list for current BusId values.")

    async def mutate(self, *args: str) -> dict[str, Any]:
        result = await self.run(self.executable, *args)
        try:
            state = await self.state()
        except ToolError as exc:
            return {"commands": [result], "state": None, "state_error": str(exc)}
        return {"commands": [result], "state": state}


def create_app(backend: Usbipd, token: str, host: str, port: int) -> ASGIApp:
    mcp = MCPServer(
        "windows-usbipd", version="0.1.0", subscriptions=False,
        instructions=(
            "Control Windows USB sharing and WSL attachment. Start with usbipd_list and usbipd_status. "
            "Use current BusId values: unplugging or switching USB modes can change them. "
            "Attach takes the device away from Windows; detach and unbind cause surprise removal in WSL. "
            "Never manipulate unrelated keyboards, mice, or active devices without user authorization. "
            "All WSL 2 distributions share the attached device; distribution selects the attach helper only."
        ),
    )

    @mcp.tool(annotations=READ_ONLY)
    async def usbipd_status() -> dict[str, Any]:
        """Read usbipd version, administrator status, and installed WSL distribution names."""
        async with backend.lock:
            version = await backend.run(backend.executable, "--version")
            return {
                "usbipd_version": version["stdout"],
                "is_admin": is_admin(),
                "wsl_distributions": await backend.distributions(),
            }

    @mcp.tool(annotations=READ_ONLY)
    async def usbipd_list() -> dict[str, Any]:
        """Read usbipd state JSON, including disconnected persisted devices.

        Devices[].BusId is null for disconnected devices. PersistedGuid means shared;
        ClientIPAddress means attached. InstanceId contains VID/PID and identity.
        """
        async with backend.lock:
            return await backend.state()

    @mcp.tool(annotations=MUTATING)
    async def usbipd_bind(busid: BusId, force: bool = False) -> dict[str, Any]:
        """Persistently share one connected USB device. Administrator rights required.

        Normally Windows retains access until attach. force=True immediately takes
        it away from Windows and should only be used for an incompatible driver.
        """
        async with backend.lock:
            await backend.device(busid)
            args = ["bind", "--busid", busid]
            if force:
                args.append("--force")
            return await backend.mutate(*args)

    @mcp.tool(annotations=MUTATING)
    async def usbipd_unbind(busid: BusId | None = None, guid: UUID | None = None) -> dict[str, Any]:
        """Stop sharing exactly one device. Specify either busid or persisted guid.

        GUID also works for unplugged devices. An attached device is immediately
        detached, causing surprise removal in the client. Removes persistent sharing.
        """
        if (busid is None) == (guid is None):
            raise ToolError("Specify exactly one of busid or guid")
        async with backend.lock:
            if busid is not None:
                return await backend.mutate("unbind", "--busid", busid)
            return await backend.mutate("unbind", "--guid", str(guid))

    @mcp.tool(annotations=MUTATING)
    async def usbipd_attach(
        busid: BusId,
        distribution: Distribution | None = None,
        auto_bind: bool = True,
        host_ip: IPvAnyAddress | None = None,
    ) -> dict[str, Any]:
        """Attach one USB device to WSL 2, making it unavailable in Windows.

        auto_bind shares it first if needed, without force. distribution is an installed
        WSL name, or omit to let usbipd choose. host_ip optionally overrides the Windows
        IP that WSL uses for USB/IP (TCP 3240), not the MCP address. Sharing persists if
        attach fails; inspect usbipd_list. No background auto-attach process is started.
        """
        async with backend.lock:
            device = await backend.device(busid)
            if distribution is not None and distribution not in await backend.distributions():
                raise ToolError(f"WSL distribution {distribution!r} is not installed; call usbipd_status")
            commands = []
            if auto_bind and device.get("PersistedGuid") is None:
                commands.append(await backend.run(backend.executable, "bind", "--busid", busid))
            args = ["attach", "--busid", busid, "--wsl"]
            if distribution is not None:
                args.append(distribution)
            if host_ip is not None:
                args.extend(["--host-ip", str(host_ip)])
            try:
                result = await backend.mutate(*args)
            except ToolError as exc:
                if commands:
                    raise ToolError(f"bind succeeded; device remains shared. attach failed: {exc}") from exc
                raise
            result["commands"] = commands + result["commands"]
            return result

    @mcp.tool(annotations=MUTATING)
    async def usbipd_detach(busid: BusId) -> dict[str, Any]:
        """Detach one USB device from WSL. Surprise removal; sharing remains enabled.

        Windows regains access unless the device was force-bound. Use unbind to
        remove persistent sharing and restore a force-bound device to Windows.
        """
        async with backend.lock:
            return await backend.mutate("detach", "--busid", busid)

    # Only the explicit listener address is trusted; no wildcard Host/Origin allowlist.
    authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    app = mcp.streamable_http_app(
        json_response=True, stateless_http=True,
        transport_security=TransportSecuritySettings(allowed_hosts=[authority], allowed_origins=[]),
    )
    return BearerAuth(app, token)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", type=IPvAnyAddress, default="127.0.0.1", help="Explicit Windows listener IP")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--timeout", type=float, default=90, help="Per-command deadline in seconds")
    parser.add_argument("--token-file", type=Path, default=TOKEN_FILE)
    args = parser.parse_args()
    if not is_admin():
        parser.error("Run this server from an elevated Windows terminal (Run as administrator)")
    if not 1 <= args.port <= 65535 or not 0 < args.timeout < float("inf"):
        parser.error("port must be 1..65535 and timeout must be finite and positive")
    if args.host.is_unspecified or args.host.is_multicast:
        parser.error("Use an explicit local IP, not 0.0.0.0/:: or a multicast address")
    token = os.environ.get("USBIPD_MCP_TOKEN")
    if token is None:
        try:
            token = args.token_file.read_text(encoding="utf-8-sig").strip()
        except OSError as exc:
            parser.error(f"Cannot read token: {exc}. Run start.ps1 or set USBIPD_MCP_TOKEN")
    if not re.fullmatch(r"[A-Za-z0-9._~+/=-]{32,512}", token):
        parser.error("Token must be 32..512 ASCII bearer-token characters")
    executable = shutil.which("usbipd.exe")
    wsl = str(Path(os.environ["SystemRoot"]) / "System32" / "wsl.exe")
    if executable is None or not Path(wsl).is_file():
        parser.error("usbipd-win and WSL must be installed and usbipd.exe available on PATH")
    try:
        version = subprocess.run(
            [executable, "--version"], capture_output=True, timeout=10,
            encoding="utf-8-sig", check=True, creationflags=subprocess.CREATE_NO_WINDOW,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        parser.error(f"Cannot run usbipd: {exc}")
    if not version.startswith("5."):
        parser.error(f"Supported usbipd-win version is 5.x; found {version}")
    host = str(args.host)
    backend = Usbipd(executable, wsl, args.timeout)
    app = create_app(backend, token, host, args.port)
    authority = f"[{host}]" if ":" in host else host
    print(f"MCP endpoint: http://{authority}:{args.port}/mcp", flush=True)
    uvicorn.run(app, host=host, port=args.port, proxy_headers=False, access_log=False)


if __name__ == "__main__":
    main()
