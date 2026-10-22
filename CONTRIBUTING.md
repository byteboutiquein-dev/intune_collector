# Contributing

## Before contributing

Open an issue before a substantial behavioral change. Security reports must
follow [SECURITY.md](SECURITY.md) and must not be filed publicly.

Never commit real customer logs, tenant identifiers, enrollment tokens,
credentials, certificates, private keys, email addresses, or device exports.
Tests must use synthetic identifiers and synthetic IME records.

## Development workflow

1. Install the .NET SDK selected by `global.json`.
2. Create a focused branch and add or update tests.
3. Run `dotnet test IntuneReliability.Collector.Tests`.
4. Run `scripts/Test-OpenSourceBoundary.ps1` in PowerShell.
5. Submit a pull request describing behavior, privacy impact, and validation.

Changes that add a log source, network endpoint, transmitted field, privilege,
or mutation capability require corresponding updates to `PRIVACY.md` and
`docs/threat-model.md`.

## Developer Certificate of Origin

Contributions use the Developer Certificate of Origin 1.1. Sign every commit:

```text
Signed-off-by: Your Name <your-email@example.com>
```

Use `git commit -s` to add the line. By signing off, you certify that you have
the right to submit the contribution under this repository's Apache-2.0
licence. The DCO text is available at https://developercertificate.org/.

