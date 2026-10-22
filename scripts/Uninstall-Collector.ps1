# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [string]$ServiceName = "IntuneReliabilityCollector",
    [string]$InstallDirectory = "$env:ProgramFiles\IntuneReliability\Collector",
    [string]$StateDirectory = "$env:ProgramData\IntuneReliability\Collector",
    [switch]$AllowUnsignedLabBuild,
    [switch]$PreserveState
)

$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from PowerShell as Administrator."
}

$policyPath = Join-Path $InstallDirectory "release-policy.json"
if (Test-Path -LiteralPath $policyPath -PathType Leaf) {
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
} elseif (-not $AllowUnsignedLabBuild) {
    throw "The installed collector has no signed release policy. Use AllowUnsignedLabBuild only to remove a controlled lab installation."
} else {
    Write-Warning "LAB ONLY: uninstalling an unsigned collector installation."
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force
        $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }
    & sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Windows could not remove service $ServiceName." }
}

Remove-Item $InstallDirectory -Recurse -Force -ErrorAction SilentlyContinue
if (-not $PreserveState) {
    Remove-Item $StateDirectory -Recurse -Force -ErrorAction SilentlyContinue
}

[pscustomobject]@{
    Service = $ServiceName
    Removed = $true
    StatePreserved = [bool]$PreserveState
}
