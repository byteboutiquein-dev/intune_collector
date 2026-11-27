// SPDX-License-Identifier: Apache-2.0

namespace IntuneReliability.Collector;

/// <summary>Retry delays that double after each failure, from a starting delay up to a ceiling.</summary>
public static class Backoff
{
    public static readonly TimeSpan Ceiling = TimeSpan.FromMinutes(15);

    public static TimeSpan Delay(int failures, TimeSpan initial)
    {
        if (failures <= 1) return initial;
        var factor = Math.Pow(2, Math.Min(failures - 1, 16));
        var delay = TimeSpan.FromTicks((long)Math.Min(initial.Ticks * factor, Ceiling.Ticks));
        return delay < initial ? initial : delay;
    }
}
