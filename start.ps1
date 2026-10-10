param(
    [string]$ListenAddress = "",
    [ValidateRange(1, 65535)][int]$Port = 8765
)

$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run start.ps1 in an administrator PowerShell terminal."
}

if (-not $ListenAddress) {
    $wslAddress = Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.InterfaceAlias -like "vEthernet (WSL*" -and $_.AddressState -eq "Preferred" } |
        Select-Object -First 1
    if ($wslAddress) {
        $ListenAddress = $wslAddress.IPAddress
    } else {
        $ListenAddress = "127.0.0.1"
        Write-Warning "No WSL virtual adapter found. Using localhost; for NAT, start WSL and rerun."
    }
}

$tokenFile = Join-Path $PSScriptRoot ".usbipd-mcp-token"
if (-not $env:USBIPD_MCP_TOKEN) {
    $newToken = -not (Test-Path -LiteralPath $tokenFile)
    if ($newToken) {
        New-Item -Path $tokenFile -ItemType File | Out-Null
    }
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($identity.User)
    foreach ($sid in @(
        $identity.User,
        [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544"),
        [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    )) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $tokenFile -AclObject $acl
    if ($newToken) {
        $bytes = New-Object byte[] 32
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        $token = [BitConverter]::ToString($bytes).Replace("-", "").ToLowerInvariant()
        [IO.File]::WriteAllText($tokenFile, $token, [Text.UTF8Encoding]::new($false))
    }
    Write-Host "Bearer token file: $tokenFile (not printed or logged)"
}

Push-Location $PSScriptRoot
try {
    if (Get-Command uv -ErrorAction SilentlyContinue) {
        & uv run --locked python server.py --host $ListenAddress --port $Port
    } else {
        $python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
        if (-not (Test-Path -LiteralPath $python)) {
            throw "Install dependencies first: python -m venv .venv; .venv\Scripts\python.exe -m pip install -e ."
        }
        & $python server.py --host $ListenAddress --port $Port
    }
    if ($LASTEXITCODE -ne 0) { throw "MCP server exited with code $LASTEXITCODE" }
} finally {
    Pop-Location
}
