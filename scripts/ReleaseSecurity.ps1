# SPDX-License-Identifier: Apache-2.0

Set-StrictMode -Version Latest

function Assert-CollectorAuthenticodeFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedPublisherSubject,
        [string]$ExpectedThumbprint
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required signed file was not found: $Path"
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Authenticode validation failed for $Path. Status: $($signature.Status)."
    }
    if (-not $signature.SignerCertificate) {
        throw "Authenticode signer certificate was not returned for $Path."
    }
    if (-not [string]::Equals(
        $signature.SignerCertificate.Subject,
        $ExpectedPublisherSubject,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Publisher validation failed for $Path. Expected '$ExpectedPublisherSubject'; received '$($signature.SignerCertificate.Subject)'."
    }
    if ($ExpectedThumbprint -and -not [string]::Equals(
        $signature.SignerCertificate.Thumbprint,
        $ExpectedThumbprint,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Signer certificate validation failed for $Path."
    }
    if (-not $signature.TimeStamperCertificate) {
        throw "A trusted timestamp is required for $Path."
    }

    return $signature
}

function Assert-CollectorReleasePackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackageDirectory,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedPublisherSubject
    )

    $manifestPath = Join-Path $PackageDirectory "Release-Manifest.ps1"
    $manifestSignature = Assert-CollectorAuthenticodeFile `
        -Path $manifestPath `
        -ExpectedPublisherSubject $ExpectedPublisherSubject

    $CollectorReleaseManifestJson = $null
    . $manifestPath
    if (-not $CollectorReleaseManifestJson) {
        throw "The signed collector release manifest did not provide release metadata."
    }

    $manifest = $CollectorReleaseManifestJson | ConvertFrom-Json
    if ($manifest.schemaVersion -ne 1) {
        throw "Unsupported collector release manifest schema."
    }
    if ($manifest.product -ne "SentVora Windows Evidence Collector") {
        throw "The package product identity is invalid."
    }
    if (-not [string]::Equals(
        $manifest.publisherSubject,
        $ExpectedPublisherSubject,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "The package publisher does not match the trusted publisher policy."
    }
    if (-not [string]::Equals(
        $manifest.signerThumbprint,
        $manifestSignature.SignerCertificate.Thumbprint,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "The release manifest signer does not match its declared certificate."
    }
    if (-not $manifest.files -or $manifest.files.Count -lt 1) {
        throw "The release manifest does not contain file integrity records."
    }

    foreach ($file in $manifest.files) {
        $relativePath = [string]$file.path
        if (-not $relativePath -or [System.IO.Path]::GetFileName($relativePath) -ne $relativePath) {
            throw "The release manifest contains an unsafe file path."
        }

        $filePath = Join-Path $PackageDirectory $relativePath
        if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
            throw "Release file listed in the manifest was not found: $relativePath"
        }

        $actualHash = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash
        if (-not [string]::Equals($actualHash, [string]$file.sha256, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Release file checksum validation failed: $relativePath"
        }

        if ([System.IO.Path]::GetExtension($relativePath) -in @(".exe", ".ps1")) {
            $null = Assert-CollectorAuthenticodeFile `
                -Path $filePath `
                -ExpectedPublisherSubject $ExpectedPublisherSubject `
                -ExpectedThumbprint ([string]$manifest.signerThumbprint)
        }
    }

    $executablePath = Join-Path $PackageDirectory "IntuneReliability.Collector.exe"
    $productVersion = (Get-Item -LiteralPath $executablePath).VersionInfo.ProductVersion
    $normalizedVersion = ([string]$productVersion).Split('+')[0]
    if (-not [string]::Equals($normalizedVersion, [string]$manifest.version, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Collector executable version does not match the signed release manifest."
    }

    return [pscustomobject]@{
        Version = [string]$manifest.version
        Runtime = [string]$manifest.runtime
        PublisherSubject = [string]$manifest.publisherSubject
        SignerThumbprint = [string]$manifest.signerThumbprint
        ManifestPath = $manifestPath
        FileCount = $manifest.files.Count
    }
}

function Read-CollectorReleasePolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InstallDirectory
    )

    $policyPath = Join-Path $InstallDirectory "release-policy.json"
    if (-not (Test-Path -LiteralPath $policyPath -PathType Leaf)) {
        throw "The installed collector release policy was not found at $policyPath."
    }

    $policy = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
    if ($policy.schemaVersion -ne 1 -or -not $policy.publisherSubject) {
        throw "The installed collector release policy is invalid."
    }

    return $policy
}
