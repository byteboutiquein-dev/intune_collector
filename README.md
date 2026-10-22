# SentVora Windows Evidence Collector

Collector `2.10.0` is the open-source, optional endpoint component for
SentVora. It distinguishes GRS deferral from reevaluation delay and uses
observed per-application ordering to separate pre-install detection from
post-install verification. ClientHealth events remain device-scoped even when
Microsoft health records contain operation or remediation GUIDs.

The collector is a read-only `.NET 8` Windows service. It reads allow-listed Microsoft Intune Management Extension logs, normalizes a bounded set of lifecycle events locally, and sends only structured evidence over outbound HTTPS.

It has no command channel. It cannot modify Intune, clear GRS, retry applications, execute PowerShell, reboot, install applications, uninstall applications, or provide a remote shell. Cursors advance only after an idempotent batch is accepted. Device credentials are protected with Windows DPAPI and can be revoked independently.

## Open-source boundary

This repository contains the complete source used to build the collector
binary and its distributed lifecycle scripts. It does **not** contain the
SentVora SaaS service, diagnosis engine, PolicyLens implementation, tenant
authorization, database, or web application. Those systems communicate with
the collector through the bounded protocol in [docs/protocol.md](docs/protocol.md)
and are not licensed by this repository.

Review these documents before deploying or contributing:

- [PRIVACY.md](PRIVACY.md) for exactly what is read, sent, and retained locally;
- [SECURITY.md](SECURITY.md) for vulnerability reporting and security properties;
- [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md) for release trust and SignPath readiness;
- [docs/threat-model.md](docs/threat-model.md) for trust boundaries and residual risks; and
- [CONTRIBUTING.md](CONTRIBUTING.md) for synthetic-test and DCO requirements.

## Current release state

- The source boundary, Apache-2.0 licensing, privacy contract, automated build,
  release policy, and export controls are implemented.
- Collector `2.10.0` native normalizer tests must pass on the Windows build host before packaging.
- Lab packaging is self-contained; the target VM does not need a separate .NET runtime.
- Unsigned lab artifacts require an explicit `-AllowUnsignedLabBuild` override and are never commercial release artifacts.
- SignPath Foundation acceptance and the first publicly signed release remain
  pending. Open sourcing the collector does not itself make an unsigned binary
  trusted.
- A customer package requires a trusted code-signing certificate. The executable, every distributed PowerShell script, and the release manifest are signed and timestamped.
- Install and update verify the exact publisher subject, signed manifest, package hashes, product identity, version, and trusted timestamp before changing the Windows service.
- Commercial release remains blocked until a production certificate signs the package and the complete two-endpoint lifecycle acceptance passes.

## Build

Run from the collector repository root on Windows PowerShell with the .NET 8 SDK:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\Build-Collector.ps1
```

Output:

```text
.artifacts\collector\SentVora-Collector-2.10.0-win-x64.zip
.artifacts\collector\SentVora-Collector-2.10.0-win-x64.zip.sha256
```

The build script runs native tests before publishing. It then creates a self-contained single-file executable, copies the service scripts, writes SHA-256 checksums, and creates a versioned ZIP. A signed build also emits and timestamps a signed release manifest covering every packaged file.

To produce a commercial signed package, install the code-signing certificate
with its private key in the build account's `CurrentUser\My` or
`LocalMachine\My` certificate store, then provide its thumbprint:

```powershell
.\scripts\Build-Collector.ps1 `
  -SigningCertificateThumbprint "CERTIFICATE_THUMBPRINT"
```

The certificate must be currently valid, include the Code Signing EKU, and
have an accessible private key. The build fails unless every signature is
valid and timestamped. `ReleaseReady=True` is emitted only after the package
passes its own signed-manifest validation. The private key must remain in the
approved signing provider's HSM and must never be added to this repository.

## Public source export

When this directory is maintained inside a private product monorepo, generate
the public-repository candidate with:

```powershell
.\scripts\Export-OpenSourceRepository.ps1
```

The export uses an explicit allowlist, rejects parent-repository references and
common secret or certificate material, scans the staged copy again, and writes
a source ZIP plus SHA-256 file under `.artifacts\open-source`. Inspect the
archive before creating or updating the public repository.

## Enrollment

1. Sign in to SentVora as the workspace owner or administrator.
2. Open **Administration > Collectors**.
3. Select the managed Windows device.
4. Select **Create enrollment**.
5. Copy the one-time token. It expires after 15 minutes and is shown only in that browser state.
6. Transfer the versioned `SentVora-Collector-<version>-win-x64.zip` and its `.sha256` file to the managed endpoint, verify the ZIP checksum, and extract it.
7. Open PowerShell as Administrator in the extracted directory.

Run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Install-Collector.ps1 `
  -ApiBaseUrl "https://your-reachable-product-origin.example" `
  -ExpectedPublisherSubject "EXACT CERTIFICATE SUBJECT FROM SENTVORA RELEASE NOTES"
```

Paste the enrollment token only when the secure prompt appears. Publisher and
package verification finishes before the token prompt or any machine change.
The installer writes the token into a SYSTEM/Administrators-only state
directory. The collector deletes the token file after exchanging it for a
DPAPI-protected device credential.

An unsigned build may be installed only in the controlled lab:

```powershell
.\Install-Collector.ps1 `
  -ApiBaseUrl "https://your-reachable-product-origin.example" `
  -AllowUnsignedLabBuild
```

## Status

Run on the managed endpoint:

```powershell
.\Get-CollectorStatus.ps1
```

Expected initial result:

```text
Installed              True
Status                 Running
Enrolled               True
EnrollmentTokenPending False
Signature              Valid
Timestamped            True
ReleasePolicyPresent   True
PublisherMatchesPolicy True
SignedReleaseTrusted   True
```

Any `SignedReleaseTrusted=False` result blocks customer acceptance.

## Upgrade

Extract the replacement package, open PowerShell as Administrator in that directory, and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Update-Collector.ps1
```

The upgrade reads the publisher from the installed release policy, validates
the complete replacement package before stopping the service, and rejects
unsigned or wrong-publisher replacements. It preserves the machine-scoped
DPAPI credential, configuration, and accepted-event cursor. It restores the
previous executable and release policy automatically if the replacement
service cannot start.

The one-time migration from an older unsigned lab installation requires the
exact production publisher and an explicit legacy-installation override:

```powershell
.\Update-Collector.ps1 `
  -ExpectedPublisherSubject "EXACT CERTIFICATE SUBJECT FROM SENTVORA RELEASE NOTES" `
  -AllowUnsignedCurrentInstallation
```

A lower signed version is rejected by default. An approved rollback requires
`-AllowDowngrade`; it still must be signed and timestamped by the trusted
publisher.

## Re-enrollment after revocation

An installed collector whose server credential was revoked must receive a new
one-time enrollment. Do not uninstall it merely to replace the credential.
Create a fresh enrollment for the same device in **Administration > Collectors**, open
PowerShell as Administrator in the extracted collector package, and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Reenroll-Collector.ps1
```

Paste the new token only into the secure prompt. The helper stops the collector,
replaces only its DPAPI credential, preserves `cursors.json`, and restarts the
service. If the token cannot be claimed, it restores the previous local
credential and leaves the cursor untouched.

## Live evidence validation

This step is a manual VM operation. Generate normal IME activity without mutating local IME state:

```powershell
Restart-Service IntuneManagementExtension -Force
Start-Sleep -Seconds 45
.\Get-CollectorStatus.ps1
```

Then refresh **Administration > Collectors**. The endpoint should show an active enrollment, a recent last-seen time, an accepted batch, and a reconstruction result. A batch appears only when an allow-listed lifecycle line is observed; ordinary unrelated log lines are intentionally ignored.

## Revocation and uninstall

Perform revocation last because it intentionally stops uploads:

1. In **Administration > Collectors**, select **Revoke** for the endpoint.
2. Generate another normal IME event and wait at least 30 seconds.
3. Verify the server does not accept a new batch and the collector does not advance its cursor.

Clean uninstall is a manual VM operation:

```powershell
.\Uninstall-Collector.ps1
```

The default uninstall verifies its script against the installed publisher
policy, then removes the service, executable, DPAPI credential, token file, and
cursors. Use `-PreserveState` only when collecting controlled troubleshooting
evidence. Removing a legacy unsigned lab install requires
`-AllowUnsignedLabBuild`.

## Licence

Original collector source is available under the
[Apache License 2.0](LICENSE). SentVora names and marks are not granted by that
licence except as needed to describe the origin of the software. See
[NOTICE](NOTICE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
