# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [ValidateSet("win-x64", "win-arm64")]
    [string]$Runtime = "win-x64",
    [string]$Configuration = "Release",
    [string]$SigningCertificateThumbprint,
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$parentRoot = Split-Path -Parent $projectRoot
$repositoryRoot = if (Test-Path -LiteralPath (Join-Path $parentRoot "package.json") -PathType Leaf) {
    $parentRoot
} else {
    $projectRoot
}
$project = Join-Path $projectRoot "IntuneReliability.Collector\IntuneReliability.Collector.csproj"
$testProject = Join-Path $projectRoot "IntuneReliability.Collector.Tests\IntuneReliability.Collector.Tests.csproj"
$artifactRoot = Join-Path $repositoryRoot ".artifacts\collector"
$publishDirectory = Join-Path $artifactRoot $Runtime
$projectXml = [xml](Get-Content -LiteralPath $project -Raw)
$version = [string]$projectXml.Project.PropertyGroup.Version
if (-not $version) { throw "Collector version is missing from the project file." }
$packagePath = Join-Path $artifactRoot "SentVora-Collector-$version-$Runtime.zip"

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw ".NET 8 SDK is required to build the collector."
}

$majorVersion = [int]((& dotnet --version).Split('.')[0])
if ($majorVersion -lt 8) {
    throw ".NET 8 SDK or newer is required to build the collector."
}

Remove-Item $publishDirectory -Recurse -Force -ErrorAction SilentlyContinue
New-Item $publishDirectory -ItemType Directory -Force | Out-Null

& dotnet test $testProject --configuration $Configuration
if ($LASTEXITCODE -ne 0) { throw "Collector unit tests failed." }

& dotnet publish $project `
    --configuration $Configuration `
    --runtime $Runtime `
    --self-contained true `
    --output $publishDirectory `
    -p:PublishSingleFile=true `
    -p:DebugType=None `
    -p:DebugSymbols=false `
    -p:IncludeNativeLibrariesForSelfExtract=true
if ($LASTEXITCODE -ne 0) { throw "Collector publish failed." }

$executable = Join-Path $publishDirectory "IntuneReliability.Collector.exe"
if (-not (Test-Path $executable)) { throw "Published collector executable was not found." }

Copy-Item (Join-Path $PSScriptRoot "Install-Collector.ps1") $publishDirectory
Copy-Item (Join-Path $PSScriptRoot "Update-Collector.ps1") $publishDirectory
Copy-Item (Join-Path $PSScriptRoot "Reenroll-Collector.ps1") $publishDirectory
Copy-Item (Join-Path $PSScriptRoot "Get-CollectorStatus.ps1") $publishDirectory
Copy-Item (Join-Path $PSScriptRoot "Uninstall-Collector.ps1") $publishDirectory
Copy-Item (Join-Path $PSScriptRoot "ReleaseSecurity.ps1") $publishDirectory
Copy-Item (Join-Path $projectRoot "README.md") $publishDirectory
Copy-Item (Join-Path $projectRoot "LICENSE") $publishDirectory
Copy-Item (Join-Path $projectRoot "NOTICE") $publishDirectory
Copy-Item (Join-Path $projectRoot "PRIVACY.md") $publishDirectory
Copy-Item (Join-Path $projectRoot "CODE_SIGNING_POLICY.md") $publishDirectory
Copy-Item (Join-Path $projectRoot "THIRD_PARTY_NOTICES.md") $publishDirectory

function Get-SigningCertificate([string]$Thumbprint) {
    $normalizedThumbprint = $Thumbprint.Replace(" ", "").ToUpperInvariant()
    $certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$normalizedThumbprint" -ErrorAction SilentlyContinue
    if (-not $certificate) {
        $certificate = Get-Item -LiteralPath "Cert:\LocalMachine\My\$normalizedThumbprint" -ErrorAction SilentlyContinue
    }
    if (-not $certificate) { throw "The requested code-signing certificate was not found." }
    if (-not $certificate.HasPrivateKey) { throw "The code-signing certificate has no accessible private key." }
    if ((Get-Date) -lt $certificate.NotBefore -or (Get-Date) -ge $certificate.NotAfter) {
        throw "The code-signing certificate is not currently valid."
    }
    $codeSigningOid = "1.3.6.1.5.5.7.3.3"
    $supportsCodeSigning = $certificate.EnhancedKeyUsageList | Where-Object { $_.ObjectId.Value -eq $codeSigningOid }
    if (-not $supportsCodeSigning) { throw "The certificate is not valid for code signing." }
    return $certificate
}

function Set-ReleaseSignature([string]$Path, [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate) {
    $signature = Set-AuthenticodeSignature `
        -LiteralPath $Path `
        -Certificate $Certificate `
        -HashAlgorithm SHA256 `
        -TimestampServer $TimestampUrl
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Signing failed for $Path. Status: $($signature.Status)."
    }
    if (-not $signature.TimeStamperCertificate) {
        throw "The signing service did not return a trusted timestamp for $Path."
    }
    return $signature
}

$certificate = $null
if ($SigningCertificateThumbprint) {
    $certificate = Get-SigningCertificate $SigningCertificateThumbprint
    $signableFiles = @($executable) + @(
        Get-ChildItem -LiteralPath $publishDirectory -Filter "*.ps1" -File |
            Select-Object -ExpandProperty FullName
    )
    foreach ($file in $signableFiles) {
        $null = Set-ReleaseSignature -Path $file -Certificate $certificate
    }
}

$hashes = Get-ChildItem $publishDirectory -File | Sort-Object Name | ForEach-Object {
    $hash = Get-FileHash $_.FullName -Algorithm SHA256
    "{0}  {1}" -f $hash.Hash.ToLowerInvariant(), $_.Name
}
Set-Content (Join-Path $publishDirectory "SHA256SUMS.txt") $hashes -Encoding Ascii

$releaseValidation = $null
if ($certificate) {
    $manifestFiles = Get-ChildItem -LiteralPath $publishDirectory -File | Sort-Object Name | ForEach-Object {
        [ordered]@{
            path = $_.Name
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $manifest = [ordered]@{
        schemaVersion = 1
        product = "SentVora Windows Evidence Collector"
        version = $version
        runtime = $Runtime
        publisherSubject = $certificate.Subject
        signerThumbprint = $certificate.Thumbprint
        createdAtUtc = [DateTime]::UtcNow.ToString("O")
        files = @($manifestFiles)
    }
    $manifestJson = $manifest | ConvertTo-Json -Depth 5
    $manifestPath = Join-Path $publishDirectory "Release-Manifest.ps1"
    $manifestScript = "`$CollectorReleaseManifestJson = @'`r`n$manifestJson`r`n'@"
    Set-Content -LiteralPath $manifestPath -Value $manifestScript -Encoding UTF8
    $null = Set-ReleaseSignature -Path $manifestPath -Certificate $certificate

    . (Join-Path $publishDirectory "ReleaseSecurity.ps1")
    $releaseValidation = Assert-CollectorReleasePackage `
        -PackageDirectory $publishDirectory `
        -ExpectedPublisherSubject $certificate.Subject
}

Remove-Item $packagePath -Force -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $publishDirectory "*") -DestinationPath $packagePath -CompressionLevel Optimal
$packageHash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash
Set-Content -LiteralPath "$packagePath.sha256" -Value "$($packageHash.ToLowerInvariant())  $([System.IO.Path]::GetFileName($packagePath))" -Encoding Ascii

[pscustomobject]@{
    Runtime = $Runtime
    Version = $version
    Package = $packagePath
    PackageSha256 = $packageHash
    Executable = $executable
    Publisher = if ($certificate) { $certificate.Subject } else { $null }
    Signed = [bool]$certificate
    Timestamped = [bool]$releaseValidation
    ReleaseReady = [bool]$releaseValidation
}
