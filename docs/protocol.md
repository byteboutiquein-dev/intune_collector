# Collector Protocol

## Enrollment

`POST /api/diagnostics/collector/claim`

Request:

```json
{ "enrollmentToken": "one-time-secret" }
```

Response:

```json
{ "deviceId": "server-device-id", "credential": "device-secret" }
```

The one-time token is deleted locally only after a successful exchange.

## Evidence upload

`POST /api/diagnostics/collector/events`

The request uses `Authorization: Bearer <device credential>` and contains:

- `idempotencyKey`;
- `collectorVersion`;
- `events`; and
- `cursors` proposed for commit after acceptance.

Each event contains only the fields defined by `CollectorEvent` in
`Models.cs`. Raw source records are not part of the protocol. Unknown event
fields may be ignored, but event meaning must not be inferred beyond an
allow-listed event type and lifecycle stage.

## Delivery guarantees

- Batches are at-least-once until accepted by the service.
- The idempotency key is derived from ordered event fingerprints.
- Local cursors advance past evidence only after a successful HTTP response.
  When a poll reads lines that contain no evidence, the cursor moves past them
  without an upload, so they are not read again.
- A cursor always ends on a complete line. A line still being written is read
  on a later poll, and a full batch stops before the next unread line.
- When IME rotates a log, the rotated file's unread lines are sent before the
  new file is read. Files are identified by their NTFS file index, which a
  rename keeps.
- Revoked credentials produce an HTTP authorization failure and cursors remain
  unchanged. The collector then retries every 15 minutes until it is
  re-enrolled. Other failures are retried with delays that double up to
  15 minutes.

This protocol documents the collector-facing contract; it does not license or
expose the SentVora server implementation.

