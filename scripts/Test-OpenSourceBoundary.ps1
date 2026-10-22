# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$resolvedRoot = (Resolve-Path -LiteralPath $Root).Path.TrimEnd("\", "/")
$requiredFiles = @(
    "LICENSE",
    "NOTICE",
    "README.md",
    "PRIVACY.md",
    "SECURITY.md",
    "CODE_SIGNING_POLICY.md",
    "THIRD_PARTY_NOTICES.md",
    "IntuneReliability.Collector\IntuneReliability.Collector.csproj",
    "IntuneReliability.Collector.Tests\IntuneReliability.Collector.Tests.csproj",
    "IntuneReliability.Collector.Tests\Fixtures\parser-contract.json"
)

$violations = [System.Collections.Generic.List[string]]::new()
foreach ($relativePath in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $resolvedRoot $relativePath) -PathType Leaf)) {
        $violations.Add("Required public file is missing: $relativePath")
    }
}

$excludedDirectoryPattern = "[\\/](?:\.git|\.artifacts|bin|obj|TestResults)[\\/]"
$forbiddenBuildDirectoryPattern = "[\\/](?:artifacts|bin|obj|TestResults)[\\/]"
$files = Get-ChildItem -LiteralPath $resolvedRoot -Recurse -File -Force |
    Where-Object {
        $_.FullName -notmatch $excludedDirectoryPattern -and
        $_.FullName -notmatch $forbiddenBuildDirectoryPattern
    }

$forbiddenExtensions = @(".pfx", ".p12", ".p8", ".key", ".snk", ".cer", ".crt")
$forbiddenNames = @(".env", ".env.local", "appsettings.Production.json", "credential.bin", "enrollment-token.txt")
foreach ($file in $files) {
    $relativePath = $file.FullName.Substring($resolvedRoot.Length).TrimStart("\", "/")
    if ($file.Extension.ToLowerInvariant() -in $forbiddenExtensions) {
        $violations.Add("Forbidden certificate or key material: $relativePath")
    }
    if ($file.Name -in $forbiddenNames) {
        $violations.Add("Forbidden configuration or credential file: $relativePath")
    }
}

$textExtensions = @(".cs", ".csproj", ".json", ".md", ".props", ".ps1", ".txt", ".yml", ".yaml")
$contentPatterns = @(
    @{ Label = "private key material"; Pattern = ("BEGIN " + "(?:RSA |EC |OPENSSH )?PRIVATE KEY") },
    @{ Label = "Supabase service-role secret"; Pattern = ("SUPABASE_" + "SERVICE_ROLE_KEY\s*[:=]\s*[^<\s]") },
    @{ Label = "Azure client secret"; Pattern = ("MICROSOFT_" + "CLIENT_SECRET\s*[:=]\s*[^<\s]") },
    @{ Label = "developer home path"; Pattern = (("/" + "Users/[^/\s]+/") + "|" + ("C:" + "\\Users\\[^\\\s]+\\")) }
)

foreach ($file in $files | Where-Object { $_.Extension.ToLowerInvariant() -in $textExtensions }) {
    $relativePath = $file.FullName.Substring($resolvedRoot.Length).TrimStart("\", "/")
    $content = Get-Content -LiteralPath $file.FullName -Raw
    foreach ($rule in $contentPatterns) {
        if ($content -match $rule.Pattern) {
            $violations.Add("Possible $($rule.Label) in $relativePath")
        }
    }
}

$projectFiles = $files | Where-Object { $_.Extension -eq ".csproj" }
foreach ($projectFile in $projectFiles) {
    $relativePath = $projectFile.FullName.Substring($resolvedRoot.Length).TrimStart("\", "/")
    $content = Get-Content -LiteralPath $projectFile.FullName -Raw
    if ($content -match "\.\.\\\.\.\\|\.\./\.\./") {
        $violations.Add("Project escapes the public repository boundary: $relativePath")
    }
}

if ($violations.Count -gt 0) {
    $message = "Open-source boundary validation failed:`n - " + ($violations -join "`n - ")
    throw $message
}

[pscustomobject]@{
    Root = $resolvedRoot
    FilesScanned = $files.Count
    RequiredFiles = $requiredFiles.Count
    BoundaryValid = $true
}
