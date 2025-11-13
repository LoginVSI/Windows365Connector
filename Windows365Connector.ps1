param(
    [Parameter(Mandatory = $true)]
    [string]$EnginePath,

    [Parameter(Mandatory = $true)]
    [string]$Email,

    [Parameter(Mandatory = $true)]
    [string]$Password,

    [Parameter(Mandatory = $true)]
    [string]$Title,

    [Parameter(Mandatory = $false)]
    [string]$TOTPSecret = $null,

    [Parameter(Mandatory = $false)]
    [int]$TimeoutSeconds = 60,

    [Parameter(Mandatory = $false)]
    [int]$TOTPTimeStep = 30,

    [Parameter(Mandatory = $false)]
    [int]$TOTPDigits = 6,

    [Parameter(Mandatory = $false)]
    [ValidateSet('SHA1', 'SHA256', 'SHA512')]
    [string]$TOTPAlgorithm = 'SHA1',

    # Optional overrides; by default we point to local files next to this PS1
    [string]$ScriptPath,
    [string]$StepsPath,
    [string]$AuthScriptPath
)

# Resolve this script's directory (PS5/PS7 safe)
$scriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptDir)) {
    $scriptDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
}

# Defaults beside this PS1
if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
    $ScriptPath = Join-Path -Path $scriptDir -ChildPath 'Windows365Connector.cs'
}
if ([string]::IsNullOrWhiteSpace($StepsPath)) {
    $StepsPath = Join-Path -Path $scriptDir -ChildPath 'Windows365Connector.json'
}
if ([string]::IsNullOrWhiteSpace($AuthScriptPath)) {
    $AuthScriptPath = Join-Path -Path $scriptDir -ChildPath 'Windows365Connector_AuthenticationWindow.ps1'
}

# ---- sanity checks ----
if (-not (Test-Path -Path $EnginePath)) { 
    Write-Error "EnginePath not found: $EnginePath"
    exit 1 
}
if (-not (Test-Path -Path $ScriptPath)) { 
    Write-Error "ScriptPath not found: $ScriptPath"
    exit 1 
}
if (-not (Test-Path -Path $StepsPath)) { 
    Write-Error "StepsPath not found (JSON is required): $StepsPath"
    exit 1 
}
if (-not (Test-Path -Path $AuthScriptPath)) { 
    Write-Error "AuthScriptPath not found: $AuthScriptPath"
    exit 1 
}

# Env fallbacks (the C# also reads these)
$env:W365_EMAIL        = $Email
$env:W365_PASSWORD     = $Password
$env:W365_TITLE        = $Title
$env:W365_STEPS        = $StepsPath
$env:TOTP_SECRET       = $TOTPSecret
$env:TOTP_TIME_STEP    = $TOTPTimeStep
$env:TOTP_DIGITS       = $TOTPDigits
$env:TOTP_ALGORITHM    = $TOTPAlgorithm
$env:W365_TIMEOUT      = $TimeoutSeconds
$env:W365_AUTH_SCRIPT  = $AuthScriptPath

# Build engine args
$engineArgs = @(
    "script=""$ScriptPath"""
    "--email=""$Email"""
    "--password=""$Password"""
    "--title=""$Title"""
    "--steps=""$StepsPath"""
    "--timeout=$TimeoutSeconds"
    "--timestep=$TOTPTimeStep"
    "--digits=$TOTPDigits"
    "--algorithm=""$TOTPAlgorithm"""
    "--authscript=""$AuthScriptPath"""
)

if (-not [string]::IsNullOrEmpty($TOTPSecret)) {
    $engineArgs += "--secret=""$TOTPSecret"""
}

Write-Host "Launching Windows365Connector:"
Write-Host "  Engine: $EnginePath"
Write-Host "  C# Script: $ScriptPath"
Write-Host "  Steps: $StepsPath"
Write-Host "  Auth Script: $AuthScriptPath"
Write-Host "  Email: $Email"
Write-Host "  Title: $Title"
Write-Host "  Timeout: $TimeoutSeconds seconds"
Write-Host "  TOTP: $(if ([string]::IsNullOrEmpty($TOTPSecret)) { 'Disabled' } else { 'Enabled' })"

& $EnginePath @engineArgs
if ($LASTEXITCODE -ne $null) { exit $LASTEXITCODE } else { exit 0 }