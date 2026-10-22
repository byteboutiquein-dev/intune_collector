// SPDX-License-Identifier: Apache-2.0

using System.Text.Json.Serialization;

namespace IntuneReliability.Collector;

public sealed record CollectorEvent(
    string EventFingerprint,
    string EventType,
    string LifecycleStage,
    string Severity,
    string? ImeApplicationId,
    DateTimeOffset? OccurredAt,
    string? SourceTimestamp,
    string SourceType,
    string SourceRecordHash,
    string Summary,
    IReadOnlyDictionary<string, object?> Attributes);

public sealed record FileCursor(string FileIdentity, long Offset);

public sealed record CollectorBatch(
    string IdempotencyKey,
    string CollectorVersion,
    IReadOnlyList<CollectorEvent> Events,
    IReadOnlyDictionary<string, FileCursor> Cursors);

public sealed record ClaimRequest(string EnrollmentToken);
public sealed record ClaimResponse(string DeviceId, string Credential);
