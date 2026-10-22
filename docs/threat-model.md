# Threat Model

## Protected assets

- endpoint privacy and raw IME log content;
- collector device credentials and one-time enrollment tokens;
- evidence integrity and cursor continuity;
- release authenticity and Windows service integrity; and
- availability of the Intune Management Extension.

## Primary threats and controls

| Threat | Control |
| --- | --- |
| Tampered release | Authenticode validation, timestamp validation, signed manifest, SHA-256 file binding, and publisher pinning |
| Credential theft | Machine-scoped DPAPI, restricted state-directory ACL, one-time token deletion, and independent server revocation |
| Raw-log disclosure | Allow-list normalizer emits fixed summaries and bounded attributes; raw lines are never serialized into events |
| Replay or duplicate ingestion | Stable event fingerprints and batch idempotency keys |
| Evidence loss after failed upload | Cursors commit only after accepted delivery |
| Server-driven endpoint mutation | No inbound listener, command channel, remediation API, script execution, or application-control capability |
| Privilege expansion | Service and lifecycle behavior is fixed at build time; changes require review and a new signed release |
| Downgrade attack | Signed updates reject lower versions unless an administrator explicitly approves a signed rollback |
| Cross-product interference | Collector opens IME logs read-only with shared access and never changes IME files, registry state, service state, or application assignments |

## Residual risks

- A local administrator can inspect or replace endpoint state.
- A compromised trusted publisher or build approval process can authorize a
  malicious release.
- SHA-256 hashes of predictable log records are operational metadata, not a
  substitute for deletion or access controls.
- Microsoft may change undocumented IME log formats. Unrecognized records are
  ignored until reviewed and tested.

Any new source, transmitted field, endpoint, privilege, or mutation capability
requires a threat-model and privacy review before merge.

