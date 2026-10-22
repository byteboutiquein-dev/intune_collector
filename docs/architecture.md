# Architecture

## Components

The public repository contains a Windows worker service, a bounded IME event
normalizer, local credential and cursor stores, an outbound API client,
lifecycle scripts, tests, and release-integrity controls.

The SentVora SaaS service, diagnosis engine, policy analysis, database schema,
tenant authorization, and user interface are separate proprietary systems and
are not included in this repository or licensed under Apache-2.0.

## Data flow

1. An administrator installs the package and supplies an HTTPS service origin
   and a one-time enrollment token.
2. The service exchanges the token for a device credential and protects that
   credential with machine-scoped DPAPI.
3. The service tails allow-listed IME logs from saved byte cursors.
4. The normalizer discards unsupported records and emits bounded metadata for
   recognized lifecycle records.
5. The API client submits an idempotent batch over HTTPS.
6. Cursors are committed only after the server accepts the batch.

## Trust boundaries

- **Administrator boundary:** installation, API origin, enrollment, service
  state, update, and uninstall require local administrative authority.
- **Endpoint boundary:** raw IME records remain local; normalized metadata
  crosses the outbound HTTPS boundary.
- **Package boundary:** production lifecycle scripts trust only a pinned
  Authenticode publisher and signed manifest.
- **Service boundary:** the collector has no inbound listener or command API.

