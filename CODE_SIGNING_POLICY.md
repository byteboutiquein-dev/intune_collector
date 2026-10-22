# Code Signing Policy

## Current policy

The public collector source is prepared for the SignPath Foundation
application process. Until acceptance and a successful signed release are
published, build artifacts are explicitly **unsigned lab builds** and are not
approved for customer deployment.

Free code signing provided by SignPath.io, certificate by SignPath Foundation.

SignPath Foundation acceptance is not implied by this repository or policy.
After SentVora obtains its own publicly trusted organization-validation
certificate, future releases may transition to that verified publisher. The
expected publisher and transition instructions will be stated in the release
notes before such a change.

## Signed material

A production release signs and timestamps:

- `IntuneReliability.Collector.exe`;
- every distributed PowerShell lifecycle script; and
- `Release-Manifest.ps1`, which binds the product, version, runtime, publisher,
  signer thumbprint, and SHA-256 hash of every packaged file.

`Install-Collector.ps1` and `Update-Collector.ps1` fail closed when the trusted
publisher, timestamp, package manifest, or file hashes do not validate.

## Build and approval

1. Source changes are reviewed through pull requests.
2. CI runs the open-source boundary check and native tests on Windows.
3. The release is built from a tagged commit using
   `scripts/Build-Collector.ps1`.
4. A maintainer compares the version, commit, dependency inventory, and release
   notes before approving signing.
5. The ZIP SHA-256 digest and verification instructions are published with the
   release.

The signing key is never stored in this repository or a general-purpose CI
secret. SignPath or the future certificate provider's compliant HSM performs
the private-key operation.

## Project roles

- Repository: [byteboutiquein-dev/intune_collector](https://github.com/byteboutiquein-dev/intune_collector).
- Committer and reviewer: [Mohanraj M](https://github.com/byteboutiquein-dev), repository owner.
- Signing approver: [Mohanraj M](https://github.com/byteboutiquein-dev), repository owner.

## Verification

On Windows, verify an extracted release with:

```powershell
Get-AuthenticodeSignature .\IntuneReliability.Collector.exe |
  Format-List Status, StatusMessage, SignerCertificate, TimeStamperCertificate

Get-FileHash .\IntuneReliability.Collector.exe -Algorithm SHA256
```

Use only publisher identities and ZIP hashes copied from the canonical release
page. Do not trust a publisher value supplied alongside an unverified archive.
