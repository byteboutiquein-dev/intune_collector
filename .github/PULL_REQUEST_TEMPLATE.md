## Summary

Describe the collector behavior changed by this pull request.

## Security and privacy

- [ ] No real endpoint logs, tenant data, credentials, tokens, or certificates are included.
- [ ] Raw IME log lines remain excluded from uploaded events.
- [ ] New sources, fields, endpoints, privileges, or mutation behavior are documented in `PRIVACY.md` and `docs/threat-model.md`.
- [ ] The change preserves the no-command-channel boundary.

## Validation

- [ ] `dotnet test IntuneReliability.Collector.Tests`
- [ ] `scripts/Test-OpenSourceBoundary.ps1`
- [ ] Windows package build, when packaging behavior changed
- [ ] Commits include a DCO `Signed-off-by` line

