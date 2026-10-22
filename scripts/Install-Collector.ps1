# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^https://')]
    [string]$ApiBaseUrl,
    [SecureString]$EnrollmentToken,
    [string]$ExpectedPublisherSubject,
    [switch]$AllowUnsignedLabBuild,
    [string]$ServiceName = "IntuneReliabilityCollector",
    [string]$InstallDirectory = "$env:ProgramFiles\IntuneReliability\Collector",
    [string]$StateDirectory = "$env:ProgramData\IntuneReliability\Collector"
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

Assert-Administrator
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw "Service $ServiceName already exists. Run Uninstall-Collector.ps1 before reinstalling."
}

Write-Host "SentVora collector privacy notice:" -ForegroundColor Cyan
Write-Host "  Reads allow-listed Microsoft Intune Management Extension log files."
Write-Host "  Sends normalized event metadata and SHA-256 source-record hashes to: $ApiBaseUrl"
Write-Host "  Does not send raw log lines or provide a remote command channel."
Write-Host "  Review PRIVACY.md in this package before continuing."

$sourceExecutable = Join-Path $PSScriptRoot "IntuneReliability.Collector.exe"
if (-not (Test-Path $sourceExecutable)) {
    throw "IntuneReliability.Collector.exe must be in the same directory as this script."
}

$manifestPath = Join-Path $PSScriptRoot "Release-Manifest.ps1"
$releaseValidation = $null
if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
    if (-not $ExpectedPublisherSubject) {
        throw "ExpectedPublisherSubject is required for a signed collector installation. Use the exact publisher from the canonical SentVora release instructions."
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
} elseif (-not $AllowUnsignedLabBuild) {
    throw "Unsigned collector packages are blocked. Use a signed SentVora release or pass AllowUnsignedLabBuild only in the controlled lab."
} else {
    Write-Warning "LAB ONLY: installing an unsigned collector package. This installation is not approved for customer use."
}

if (-not $EnrollmentToken) {
    $EnrollmentToken = Read-Host "Paste the one-time collector enrollment token" -AsSecureString
}
$clearToken = ConvertFrom-SecureToken $EnrollmentToken
if ($clearToken -notmatch '^enroll_[A-Za-z0-9_-]{40,}$') {
    throw "The collector enrollment token format is invalid."
}

New-Item $InstallDirectory -ItemType Directory -Force | Out-Null
New-Item $StateDirectory -ItemType Directory -Force | Out-Null
& icacls.exe $StateDirectory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not secure the collector state directory." }

$installedExecutable = Join-Path $InstallDirectory "IntuneReliability.Collector.exe"
Copy-Item $sourceExecutable $installedExecutable -Force
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
        installedAtUtc = [DateTime]::UtcNow.ToString("O")
    } | ConvertTo-Json | Set-Content (Join-Path $InstallDirectory "release-policy.json") -Encoding UTF8
}

$configuration = @{
    Collector = @{
        ApiBaseUrl = $ApiBaseUrl.TrimEnd('/')
        PollSeconds = 30
        MaximumEventsPerBatch = 250
        EnrollmentTokenPath = (Join-Path $StateDirectory "enrollment-token.txt")
    }
}
$configuration | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $InstallDirectory "appsettings.json") -Encoding UTF8
$clearToken | Set-Content (Join-Path $StateDirectory "enrollment-token.txt") -NoNewline -Encoding Ascii
$clearToken = $null

$binaryPath = '"{0}"' -f $installedExecutable
New-Service -Name $ServiceName `
    -BinaryPathName $binaryPath `
    -DisplayName "Intune Reliability Evidence Collector" `
    -Description "Read-only normalized Intune Management Extension evidence collector." `
    -StartupType Automatic | Out-Null
& sc.exe config $ServiceName start= delayed-auto | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000 | Out-Null
Start-Service $ServiceName

$credentialPath = Join-Path $StateDirectory "credential.bin"
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline -and -not (Test-Path $credentialPath)) {
    Start-Sleep -Seconds 2
}

if (-not (Test-Path $credentialPath)) {
    Write-Warning "The service was installed, but enrollment did not complete within 90 seconds. Run Get-CollectorStatus.ps1."
} else {
    Write-Host "Collector enrolled. The credential is protected with machine-scoped DPAPI." -ForegroundColor Green
}

& (Join-Path $PSScriptRoot "Get-CollectorStatus.ps1") `
    -ServiceName $ServiceName `
    -InstallDirectory $InstallDirectory `
    -StateDirectory $StateDirectory
