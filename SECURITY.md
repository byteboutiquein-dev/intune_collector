# Security Policy

## Supported versions

Security fixes are provided for the latest published collector release. Older
versions may be asked to upgrade before a report is investigated.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue. Use the private
**Report a vulnerability** form in this repository's **Security** tab. Include:

- the affected collector version and Windows version;
- reproduction steps and expected impact;
- relevant logs with credentials, enrollment tokens, tenant identifiers,
  email addresses, and device identifiers removed; and
- whether the issue is already public or actively exploited.

The maintainers aim to acknowledge a report within five business days. A
status update or remediation plan will follow after triage. This is a target,
not a service-level agreement.

## Security properties

- Collection is read-only and limited to allow-listed IME log files.
- Raw log lines are not uploaded.
- Upload is outbound HTTPS only; there is no remote command channel.
- Device credentials are protected by Windows machine-scoped DPAPI.
- Cursors advance only after the server accepts an idempotent batch.
- Production installation and update fail closed unless package signatures,
  publisher identity, timestamps, and manifest hashes validate.

See [PRIVACY.md](PRIVACY.md), [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md),
and [docs/threat-model.md](docs/threat-model.md) for the complete boundary.

