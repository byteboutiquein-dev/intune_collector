# Collector Privacy Notice

## Purpose

The SentVora Windows Evidence Collector provides endpoint-side evidence about
Microsoft Intune Management Extension (IME) application processing. It is an
optional component installed by an authorized administrator.

## Files read

The service opens these files with shared read access when they exist:

- `AppWorkload.log`
- `AppActionProcessor.log`
- `AgentExecutor.log`
- `ClientHealth.log`
- `IntuneManagementExtension.log`

All files are under
`C:\ProgramData\Microsoft\IntuneManagementExtension\Logs`. The collector does
not scan arbitrary directories, read application payloads, or read document
content.

## Data sent

Only recognized lifecycle records produce an event. Each event can contain:

- an event fingerprint and SHA-256 hash of the source record;
- an allow-listed event type, lifecycle stage, severity, and source type;
- the Intune application GUID when the recognized record contains one;
- the source timestamp when present;
- a fixed, generated summary that does not contain the raw log line; and
- bounded attributes such as an installer exit code, dependency identifiers,
  or documented Intune enforcement-state values.

The upload batch also contains the collector version, an idempotency key, and
per-file byte cursors needed for accepted-delivery continuity.

## Data not sent

The collector does not intentionally upload:

- raw IME log lines;
- usernames, email addresses, user principal names, or free-form log text;
- application binaries, scripts, installation content, or diagnostic ZIPs;
- passwords, Microsoft access tokens, browser data, or local files outside the
  allow-listed IME log directory; or
- command output requested by the server.

Unknown and unsupported log records are ignored. The source-record hash is
evidence of record identity, not an anonymization guarantee for predictable
input, and should be handled as operational metadata.

## Network behavior

The administrator explicitly supplies the HTTPS SentVora service origin during
installation. The collector calls only:

- `POST /api/diagnostics/collector/claim` once per enrollment; and
- `POST /api/diagnostics/collector/events` for normalized evidence batches.

There is no inbound listener and no remote command, remediation, script, or
software-installation channel.

## Local storage

- The device credential is encrypted with Windows machine-scoped DPAPI.
- File cursors and non-secret configuration are stored under
  `C:\ProgramData\IntuneReliability\Collector`.
- The one-time enrollment token is removed after successful exchange.
- The state directory is restricted to `SYSTEM` and local Administrators by
  the installation script.

## Administrator control

An administrator can stop or disable the `IntuneReliabilityCollector` Windows
service to stop collection immediately, revoke its credential in SentVora, or
run `Uninstall-Collector.ps1` to remove the service and local state. SentVora
workspace retention and deletion settings govern evidence already accepted by
the service.

## Changes

Privacy-impacting changes require maintainer review, an updated notice, and
tests proving that raw log content remains excluded. Release notes must call
out any new source file, endpoint, or transmitted field.

