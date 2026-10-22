# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [SecureString]$EnrollmentToken,
    [string]$ServiceName = "IntuneReliabilityCollector",
    [string]$StateDirectory = "$env:ProgramData\IntuneReliability\Collector",
    [string]$InstallDirectory = "$env:ProgramFiles\IntuneReliability\Collector",
    [switch]$AllowUnsignedLabBuild
)

$ErrorActionPreference = "Stop"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from PowerShell as Administrator."
    }
}

function ConvertFrom-SecureToken([SecureString]$SecureToken) {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureToken)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

function Get-FileHashValue([string]$Path) {
    if (-not (Test-Path $Path)) { return $null }
    return (Get-FileHash $Path -Algorithm SHA256).Hash
}

function Assert-TrustedMutationScript {
    $policyPath = Join-Path $InstallDirectory "release-policy.json"
    if (-not (Test-Path -LiteralPath $policyPath -PathType Leaf)) {
        if ($AllowUnsignedLabBuild) {
            Write-Warning "LAB ONLY: re-enrolling an unsigned collector installation."
            return
        }
        throw "The installed collector has no signed release policy. Unsigned re-enrollment is blocked outside the controlled lab."
    }

    $policy = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
    if ($policy.schemaVersion -ne 1 -or -not $policy.publisherSubject) {
        throw "The installed collector release policy is invalid."
    }
    $releaseSecurityPath = Join-Path $PSScriptRoot "ReleaseSecurity.ps1"
    $helperSignature = Get-AuthenticodeSignature -LiteralPath $releaseSecurityPath
    if ($helperSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        -not $helperSignature.SignerCertificate -or
        -not [string]::Equals($helperSignature.SignerCertificate.Subject, [string]$policy.publisherSubject, [System.StringComparison]::OrdinalIgnoreCase) -or
        -not $helperSignature.TimeStamperCertificate) {
        throw "ReleaseSecurity.ps1 is not signed and timestamped by the installed trusted publisher."
    }
    . $releaseSecurityPath
    $null = Assert-CollectorAuthenticodeFile `
        -Path $PSCommandPath `
        -ExpectedPublisherSubject ([string]$policy.publisherSubject)
}

Assert-Administrator
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $service) {
    throw "Service $ServiceName is not installed. Use Install-Collector.ps1 for a first installation."
}
if (-not (Test-Path $StateDirectory)) {
    throw "Collector state directory $StateDirectory does not exist."
}
Assert-TrustedMutationScript

if (-not $EnrollmentToken) {
    $EnrollmentToken = Read-Host "Paste the new one-time collector enrollment token" -AsSecureString
}
$clearToken = ConvertFrom-SecureToken $EnrollmentToken
if ($clearToken -notmatch '^enroll_[A-Za-z0-9_-]{40,}$') {
    $clearToken = $null
    throw "The collector enrollment token format is invalid."
}

$credentialPath = Join-Path $StateDirectory "credential.bin"
$credentialBackupPath = Join-Path $StateDirectory "credential.bin.pre-reenrollment"
$tokenPath = Join-Path $StateDirectory "enrollment-token.txt"
$cursorPath = Join-Path $StateDirectory "cursors.json"

if (Test-Path $credentialBackupPath) {
    $clearToken = $null
    throw "A previous re-enrollment backup exists at $credentialBackupPath. Resolve it before retrying."
}

$cursorWasPresent = Test-Path $cursorPath
$cursorHashBefore = Get-FileHashValue $cursorPath
$credentialHashBefore = Get-FileHashValue $credentialPath

try {
    if ($service.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force
        $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }

    if (Test-Path $credentialPath) {
        Move-Item $credentialPath $credentialBackupPath
    }

    $clearToken | Set-Content $tokenPath -NoNewline -Encoding Ascii
    $clearToken = $null
    Start-Service -Name $ServiceName
    $service.WaitForStatus("Running", [TimeSpan]::FromSeconds(30))

    $deadline = (Get-Date).AddSeconds(90)
    do {
        Start-Sleep -Seconds 2
        $credentialHashAfter = Get-FileHashValue $credentialPath
        $enrollmentComplete = $credentialHashAfter -and
            -not (Test-Path $tokenPath) -and
            $credentialHashAfter -ne $credentialHashBefore
    } while ((Get-Date) -lt $deadline -and -not $enrollmentComplete)

    if (-not $enrollmentComplete) {
        throw "Collector re-enrollment did not complete within 90 seconds."
    }

    Remove-Item $credentialBackupPath -Force -ErrorAction SilentlyContinue
} catch {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Remove-Item $tokenPath -Force -ErrorAction SilentlyContinue
    Remove-Item $credentialPath -Force -ErrorAction SilentlyContinue
    if (Test-Path $credentialBackupPath) {
        Move-Item $credentialBackupPath $credentialPath -Force
    }
    Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $clearToken = $null
    throw
}

$cursorHashAfter = Get-FileHashValue $cursorPath

[pscustomobject]@{
    Service = $ServiceName
    Status = (Get-Service $ServiceName).Status
    Reenrolled = $true
    CredentialReplaced = (Get-FileHashValue $credentialPath) -ne $credentialHashBefore
    EnrollmentTokenRemoved = -not (Test-Path $tokenPath)
    CursorWasPresent = $cursorWasPresent
    CursorPreserved = $cursorHashBefore -eq $cursorHashAfter
}
