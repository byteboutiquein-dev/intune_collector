# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [switch]$KeepStaging
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$sourceRoot = Split-Path -Parent $PSScriptRoot
$parentRoot = Split-Path -Parent $sourceRoot
$projectPath = Join-Path $sourceRoot "IntuneReliability.Collector\IntuneReliability.Collector.csproj"
$projectXml = [xml](Get-Content -LiteralPath $projectPath -Raw)
$version = [string]$projectXml.Project.PropertyGroup.Version
if (-not $version) { throw "Collector version is missing from the project file." }

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $parentRoot ".artifacts\open-source"
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$repositoryName = "sentvora-windows-evidence-collector-$version"
$stagingRoot = Join-Path $OutputDirectory $repositoryName
$archivePath = Join-Path $OutputDirectory "$repositoryName.zip"

& (Join-Path $PSScriptRoot "Test-OpenSourceBoundary.ps1") -Root $sourceRoot | Out-Null

Remove-Item -LiteralPath $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "$archivePath.sha256" -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $stagingRoot -Force | Out-Null

$allowedTopLevelFiles = @(
    ".gitattributes",
    ".gitignore",
    "CODE_SIGNING_POLICY.md",
    "CONTRIBUTING.md",
    "Directory.Build.props",
    "LICENSE",
    "NOTICE",
    "PRIVACY.md",
    "README.md",
    "SECURITY.md",
    "SUPPORT.md",
    "THIRD_PARTY_NOTICES.md",
    "global.json"
)
$allowedDirectories = @(
    ".github",
    "docs",
    "IntuneReliability.Collector",
    "IntuneReliability.Collector.Tests",
    "scripts"
)

foreach ($fileName in $allowedTopLevelFiles) {
    $sourcePath = Join-Path $sourceRoot $fileName
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        throw "Public export allowlist file is missing: $fileName"
    }
    Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $stagingRoot $fileName)
}

foreach ($directoryName in $allowedDirectories) {
    $sourceDirectory = Join-Path $sourceRoot $directoryName
    if (-not (Test-Path -LiteralPath $sourceDirectory -PathType Container)) {
        throw "Public export allowlist directory is missing: $directoryName"
    }
    $sourcePrefix = $sourceDirectory.TrimEnd("\", "/")
    Get-ChildItem -LiteralPath $sourceDirectory -Recurse -File -Force |
        Where-Object { $_.FullName -notmatch "[\\/](?:artifacts|bin|obj|\.artifacts|TestResults)[\\/]" } |
        ForEach-Object {
            $relativePath = $_.FullName.Substring($sourcePrefix.Length).TrimStart("\", "/")
            $destinationPath = Join-Path (Join-Path $stagingRoot $directoryName) $relativePath
            $destinationDirectory = Split-Path -Parent $destinationPath
            New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
            Copy-Item -LiteralPath $_.FullName -Destination $destinationPath
        }
}

& (Join-Path $stagingRoot "scripts\Test-OpenSourceBoundary.ps1") -Root $stagingRoot | Out-Null

Compress-Archive -LiteralPath $stagingRoot -DestinationPath $archivePath -CompressionLevel Optimal
$archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$archivePath.sha256" -Value "$archiveHash  $([System.IO.Path]::GetFileName($archivePath))" -Encoding Ascii

if (-not $KeepStaging) {
    Remove-Item -LiteralPath $stagingRoot -Recurse -Force
}

[pscustomobject]@{
    Version = $version
    Archive = $archivePath
    Sha256 = $archiveHash
    StagingPreserved = [bool]$KeepStaging
    ReadyForPublicRepositoryReview = $true
}
