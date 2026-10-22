# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [string]$ExpectedPublisherSubject,
    [switch]$AllowUnsignedLabBuild,
    [switch]$AllowUnsignedCurrentInstallation,
    [switch]$AllowDowngrade,
    [string]$ServiceName = "IntuneReliabilityCollector",
    [string]$InstallDirectory = "$env:ProgramFiles\IntuneReliability\Collector",
    [string]$StateDirectory = "$env:ProgramData\IntuneReliability\Collector"
)

$ErrorActionPreference = "Stop"

function Test-PublisherSubject([string]$Actual, [string]$Expected) {
    return [string]::Equals($Actual, $Expected, [System.StringComparison]::OrdinalIgnoreCase)
}

function Assert-ReleaseSecurityHelper([string]$Path, [string]$PublisherSubject) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "ReleaseSecurity.ps1 is missing from the collector package."
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        -not $signature.SignerCertificate -or
        -not (Test-PublisherSubject $signature.SignerCertificate.Subject $PublisherSubject) -or
        -not $signature.TimeStamperCertificate) {
        throw "ReleaseSecurity.ps1 is not signed and timestamped by the trusted publisher."
    }
}

function ConvertTo-Version([string]$Value, [string]$Label) {
    $normalized = $Value.Split('+')[0]
    try { return [version]$normalized }
    catch { throw "$Label '$Value' is not a valid release version." }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from PowerShell as Administrator."
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $service) {
    throw "Service $ServiceName is not installed. Use Install-Collector.ps1 for a first installation."
}

$sourceExecutable = Join-Path $PSScriptRoot "IntuneReliability.Collector.exe"
$installedExecutable = Join-Path $InstallDirectory "IntuneReliability.Collector.exe"
$credentialPath = Join-Path $StateDirectory "credential.bin"
$cursorPath = Join-Path $StateDirectory "cursors.json"
$policyPath = Join-Path $InstallDirectory "release-policy.json"
$manifestPath = Join-Path $PSScriptRoot "Release-Manifest.ps1"
if (-not (Test-Path -LiteralPath $sourceExecutable -PathType Leaf)) { throw "The replacement collector executable is missing." }
if (-not (Test-Path -LiteralPath $installedExecutable -PathType Leaf)) { throw "The installed collector executable is missing." }

$installedPolicy = $null
if (Test-Path -LiteralPath $policyPath -PathType Leaf) {
    $installedPolicy = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
    if ($installedPolicy.schemaVersion -ne 1 -or -not $installedPolicy.publisherSubject) {
        throw "The installed collector release policy is invalid."
    }
    if ($ExpectedPublisherSubject -and -not (Test-PublisherSubject $ExpectedPublisherSubject $installedPolicy.publisherSubject)) {
        throw "ExpectedPublisherSubject does not match the installed collector trust policy."
    }
    $ExpectedPublisherSubject = [string]$installedPolicy.publisherSubject
}

$releaseValidation = $null
if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
    if (-not $ExpectedPublisherSubject) {
        throw "ExpectedPublisherSubject is required when upgrading an unsigned legacy installation to a signed release."
    }
    if (-not $installedPolicy -and -not $AllowUnsignedCurrentInstallation) {
        throw "The current installation has no signed release policy. Pass AllowUnsignedCurrentInstallation only for the controlled one-time migration to a signed release."
    }
    $releaseSecurityPath = Join-Path $PSScriptRoot "ReleaseSecurity.ps1"
    Assert-ReleaseSecurityHelper -Path $releaseSecurityPath -PublisherSubject $ExpectedPublisherSubject
    . $releaseSecurityPath
    $null = Assert-CollectorAuthenticodeFile `
        -Path $PSCommandPath `
        -ExpectedPublisherSubject $ExpectedPublisherSubject
    $releaseValidation = Assert-CollectorReleasePackage `
        -PackageDirectory $PSScriptRoot `
        -ExpectedPublisherSubject $ExpectedPublisherSubject
    if ($installedPolicy) {
        $null = Assert-CollectorAuthenticodeFile `
            -Path $installedExecutable `
            -ExpectedPublisherSubject $ExpectedPublisherSubject
    }
} elseif (-not $AllowUnsignedLabBuild) {
    throw "Unsigned collector updates are blocked. Use a signed SentVora release or pass AllowUnsignedLabBuild only in the controlled lab."
} elseif ($installedPolicy) {
    throw "A signed collector installation cannot be downgraded to an unsigned lab package."
} else {
    Write-Warning "LAB ONLY: applying an unsigned collector update. This package is not approved for customer use."
}

$sourceVersionText = if ($releaseValidation) {
    $releaseValidation.Version
} else {
    (Get-Item -LiteralPath $sourceExecutable).VersionInfo.ProductVersion
}
$installedVersionText = (Get-Item -LiteralPath $installedExecutable).VersionInfo.ProductVersion
$sourceVersion = ConvertTo-Version -Value $sourceVersionText -Label "Replacement version"
$installedVersion = ConvertTo-Version -Value $installedVersionText -Label "Installed version"
if ($sourceVersion -lt $installedVersion -and -not $AllowDowngrade) {
    throw "Collector downgrade from $installedVersion to $sourceVersion is blocked. Use AllowDowngrade only for an approved rollback signed by the trusted publisher."
}

$backupExecutable = "$installedExecutable.previous"
$backupPolicy = "$policyPath.previous"
$credentialPresent = Test-Path -LiteralPath $credentialPath
$cursorPresent = Test-Path -LiteralPath $cursorPath

try {
    Stop-Service $ServiceName -Force
    Copy-Item -LiteralPath $installedExecutable -Destination $backupExecutable -Force
    if (Test-Path -LiteralPath $policyPath) {
        Copy-Item -LiteralPath $policyPath -Destination $backupPolicy -Force
    }
    Copy-Item -LiteralPath $sourceExecutable -Destination $installedExecutable -Force

    if ($releaseValidation) {
        $sourceHash = (Get-FileHash -LiteralPath $sourceExecutable -Algorithm SHA256).Hash
        $installedHash = (Get-FileHash -LiteralPath $installedExecutable -Algorithm SHA256).Hash
        if (-not [string]::Equals($sourceHash, $installedHash, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "The installed collector executable does not match the verified release package."
        }
        $null = Assert-CollectorAuthenticodeFile `
            -Path $installedExecutable `
            -ExpectedPublisherSubject $releaseValidation.PublisherSubject `
            -ExpectedThumbprint $releaseValidation.SignerThumbprint
        [ordered]@{
            schemaVersion = 1
            publisherSubject = $releaseValidation.PublisherSubject
            signerThumbprint = $releaseValidation.SignerThumbprint
            installedVersion = $releaseValidation.Version
            installedAtUtc = if ($installedPolicy) { $installedPolicy.installedAtUtc } else { [DateTime]::UtcNow.ToString("O") }
            updatedAtUtc = [DateTime]::UtcNow.ToString("O")
        } | ConvertTo-Json | Set-Content -LiteralPath $policyPath -Encoding UTF8
    }

    Start-Service $ServiceName
    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
    Remove-Item -LiteralPath $backupExecutable -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $backupPolicy -Force -ErrorAction SilentlyContinue
} catch {
    if (Test-Path -LiteralPath $backupExecutable) {
        Copy-Item -LiteralPath $backupExecutable -Destination $installedExecutable -Force
    }
    if (Test-Path -LiteralPath $backupPolicy) {
        Copy-Item -LiteralPath $backupPolicy -Destination $policyPath -Force
    } elseif ($releaseValidation) {
        Remove-Item -LiteralPath $policyPath -Force -ErrorAction SilentlyContinue
    }
    Start-Service $ServiceName -ErrorAction SilentlyContinue
    throw
}

[pscustomobject]@{
    Service = $ServiceName
    Status = (Get-Service $ServiceName).Status
    PreviousVersion = $installedVersion.ToString()
    Version = (Get-Item -LiteralPath $installedExecutable).VersionInfo.ProductVersion
    Publisher = if ($releaseValidation) { $releaseValidation.PublisherSubject } else { "Unsigned lab build" }
    SignedRelease = [bool]$releaseValidation
    CredentialPreserved = $credentialPresent -and (Test-Path -LiteralPath $credentialPath)
    CursorPreserved = $cursorPresent -and (Test-Path -LiteralPath $cursorPath)
    EnrollmentRequired = -not (Test-Path -LiteralPath $credentialPath)
}
