import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const reenrollPath = new URL("../scripts/Reenroll-Collector.ps1", import.meta.url);
const buildPath = new URL("../scripts/Build-Collector.ps1", import.meta.url);
const installPath = new URL("../scripts/Install-Collector.ps1", import.meta.url);
const updatePath = new URL("../scripts/Update-Collector.ps1", import.meta.url);
const uninstallPath = new URL("../scripts/Uninstall-Collector.ps1", import.meta.url);
const statusPath = new URL("../scripts/Get-CollectorStatus.ps1", import.meta.url);
const releaseSecurityPath = new URL("../scripts/ReleaseSecurity.ps1", import.meta.url);
const openSourceExportPath = new URL("../scripts/Export-OpenSourceRepository.ps1", import.meta.url);
const openSourceBoundaryPath = new URL("../scripts/Test-OpenSourceBoundary.ps1", import.meta.url);

test("collector re-enrollment replaces only credentials and preserves cursors", async () => {
  const source = await readFile(reenrollPath, "utf8");

  assert.match(source, /Read-Host .* -AsSecureString/);
  assert.match(source, /credential\.bin\.pre-reenrollment/);
  assert.match(source, /CursorPreserved/);
  assert.doesNotMatch(source, /Remove-Item \$cursorPath/);
  assert.doesNotMatch(source, /Remove-Item \$StateDirectory/);
});

test("collector release package includes the re-enrollment helper", async () => {
  const source = await readFile(buildPath, "utf8");
  assert.match(source, /Copy-Item .*Reenroll-Collector\.ps1/);
  assert.match(source, /Copy-Item .*ReleaseSecurity\.ps1/);
  assert.match(source, /Copy-Item .*LICENSE/);
  assert.match(source, /Copy-Item .*PRIVACY\.md/);
  assert.match(source, /Copy-Item .*CODE_SIGNING_POLICY\.md/);
});

test("collector source export is allowlisted and scans the staged repository", async () => {
  const [exportSource, boundarySource, license, privacy, signingPolicy] = await Promise.all([
    readFile(openSourceExportPath, "utf8"),
    readFile(openSourceBoundaryPath, "utf8"),
    readFile(new URL("../LICENSE", import.meta.url), "utf8"),
    readFile(new URL("../PRIVACY.md", import.meta.url), "utf8"),
    readFile(new URL("../CODE_SIGNING_POLICY.md", import.meta.url), "utf8")
  ]);

  assert.match(exportSource, /allowedTopLevelFiles/);
  assert.match(exportSource, /allowedDirectories/);
  assert.match(exportSource, /Test-OpenSourceBoundary\.ps1.*-Root \$stagingRoot/);
  assert.doesNotMatch(exportSource, /"src"|"supabase"|"package\.json"/);
  assert.match(boundarySource, /Forbidden certificate or key material/);
  assert.match(boundarySource, /Project escapes the public repository boundary/);
  assert.match(license, /Apache License\s+Version 2\.0/);
  assert.match(privacy, /raw IME log lines/);
  assert.match(signingPolicy, /SignPath Foundation/);
});

test("signed collector builds cover executable, scripts, manifest, and package checksum", async () => {
  const source = await readFile(buildPath, "utf8");

  assert.match(source, /Get-SigningCertificate/);
  assert.match(source, /1\.3\.6\.1\.5\.5\.7\.3\.3/);
  assert.match(source, /Set-AuthenticodeSignature/);
  assert.match(source, /TimeStamperCertificate/);
  assert.match(source, /Release-Manifest\.ps1/);
  assert.match(source, /Assert-CollectorReleasePackage/);
  assert.match(source, /SentVora-Collector-\$version-\$Runtime\.zip/);
  assert.match(source, /PackageSha256/);
  assert.match(source, /ReleaseReady = \[bool\]\$releaseValidation/);
});

test("collector package validation is pinned to publisher and signed hashes", async () => {
  const source = await readFile(releaseSecurityPath, "utf8");

  assert.match(source, /SignatureStatus\]::Valid/);
  assert.match(source, /ExpectedPublisherSubject/);
  assert.match(source, /ExpectedThumbprint/);
  assert.match(source, /TimeStamperCertificate/);
  assert.match(source, /Get-FileHash .*SHA256/);
  assert.match(source, /unsafe file path/);
  assert.match(source, /SentVora Windows Evidence Collector/);
  assert.match(source, /executable version does not match/);
});

test("commercial install validates the signed release before token or machine changes", async () => {
  const source = await readFile(installPath, "utf8");
  const packageValidation = source.indexOf("Assert-CollectorReleasePackage");
  const tokenPrompt = source.indexOf('Read-Host "Paste the one-time collector enrollment token"');
  const serviceCreation = source.indexOf("New-Service -Name");

  assert.ok(packageValidation >= 0);
  assert.ok(packageValidation < tokenPrompt);
  assert.ok(packageValidation < serviceCreation);
  assert.match(source, /Unsigned collector packages are blocked/);
  assert.match(source, /ExpectedPublisherSubject is required/);
  assert.match(source, /release-policy\.json/);
  assert.match(source, /installed collector executable does not match/);
});

test("collector update validates before stopping service and protects rollback state", async () => {
  const source = await readFile(updatePath, "utf8");
  const packageValidation = source.indexOf("Assert-CollectorReleasePackage");
  const stopService = source.indexOf("Stop-Service $ServiceName -Force");

  assert.ok(packageValidation >= 0);
  assert.ok(packageValidation < stopService);
  assert.match(source, /Unsigned collector updates are blocked/);
  assert.match(source, /AllowUnsignedCurrentInstallation/);
  assert.match(source, /AllowDowngrade/);
  assert.match(source, /release-policy\.json/);
  assert.match(source, /backupPolicy/);
  assert.match(source, /CredentialPreserved/);
  assert.match(source, /CursorPreserved/);
});

test("credential and uninstall mutations enforce the installed publisher policy", async () => {
  const [reenroll, uninstall] = await Promise.all([
    readFile(reenrollPath, "utf8"),
    readFile(uninstallPath, "utf8")
  ]);

  for (const source of [reenroll, uninstall]) {
    assert.match(source, /release-policy\.json/);
    assert.match(source, /Assert-CollectorAuthenticodeFile/);
    assert.match(source, /AllowUnsignedLabBuild/);
  }
});

test("collector status exposes signed-release trust evidence", async () => {
  const source = await readFile(statusPath, "utf8");

  assert.match(source, /PublisherMatchesPolicy/);
  assert.match(source, /SignedReleaseTrusted/);
  assert.match(source, /Timestamped/);
  assert.match(source, /ReleasePolicyPresent/);
});
