// SPDX-License-Identifier: Apache-2.0

namespace IntuneReliability.Collector;

public sealed class CollectorOptions
{
    public required string ApiBaseUrl { get; init; }
    public int PollSeconds { get; init; } = 30;
    public int MaximumEventsPerBatch { get; init; } = 250;
    public string EnrollmentTokenPath { get; init; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "IntuneReliability", "Collector", "enrollment-token.txt");
}
