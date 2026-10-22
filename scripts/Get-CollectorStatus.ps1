# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [string]$ServiceName = "IntuneReliabilityCollector",
    [string]$InstallDirectory = "$env:ProgramFiles\IntuneReliability\Collector",
    [string]$StateDirectory = "$env:ProgramData\IntuneReliability\Collector"
)

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$executable = Join-Path $InstallDirectory "IntuneReliability.Collector.exe"
$signature = if (Test-Path $executable) { Get-AuthenticodeSignature $executable } else { $null }
$policyPath = Join-Path $InstallDirectory "release-policy.json"
$policy = if (Test-Path -LiteralPath $policyPath -PathType Leaf) {
    try { Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json }
    catch { $null }
} else { $null }
$publisherMatchesPolicy = [bool]($signature -and $signature.SignerCertificate -and $policy -and
    [string]::Equals(
        $signature.SignerCertificate.Subject,
        [string]$policy.publisherSubject,
        [System.StringComparison]::OrdinalIgnoreCase
    ))
$signedReleaseTrusted = [bool]($signature -and
    $signature.Status -eq [System.Management.Automation.SignatureStatus]::Valid -and
    $signature.TimeStamperCertificate -and
    $publisherMatchesPolicy)
$cursorPath = Join-Path $StateDirectory "cursors.json"
$cursorModified = if (Test-Path $cursorPath) { (Get-Item $cursorPath).LastWriteTime } else { $null }

[pscustomobject]@{
    Service = $ServiceName
    Installed = [bool]$service
    Status = if ($service) { $service.Status } else { "NotInstalled" }
    StartupType = if ($service) { $service.StartType } else { $null }
    Enrolled = Test-Path (Join-Path $StateDirectory "credential.bin")
    EnrollmentTokenPending = Test-Path (Join-Path $StateDirectory "enrollment-token.txt")
    CursorPresent = Test-Path $cursorPath
    LastCursorWrite = $cursorModified
    Signature = if ($signature) { $signature.Status } else { "NotPresent" }
    Publisher = if ($signature -and $signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
    Timestamped = [bool]($signature -and $signature.TimeStamperCertificate)
    ReleasePolicyPresent = [bool]$policy
    PublisherMatchesPolicy = $publisherMatchesPolicy
    SignedReleaseTrusted = $signedReleaseTrusted
    Executable = $executable
}
