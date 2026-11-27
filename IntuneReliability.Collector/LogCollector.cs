// SPDX-License-Identifier: Apache-2.0

namespace IntuneReliability.Collector;

/// <summary>
/// Collects events from one log source into a batch and returns the cursor to save once the batch is accepted.
/// When IME has rotated the log (AppWorkload.log renamed to AppWorkload-yyyyMMdd-HHmmss.log), the rotated file's
/// unread tail is finished first, so lines written between the last poll and the rotation are not lost.
/// </summary>
public sealed class LogCollector(Func<string, string, CollectorEvent?> normalize, Func<string, string?> identityOf)
{
    private readonly record struct ReadResult(FileCursor Cursor, bool Finished);

    public FileCursor? Collect(string source, string path, FileCursor? cursor, List<CollectorEvent> events, int capacity)
    {
        if (!File.Exists(path)) return cursor;
        var currentIdentity = identityOf(path) ?? LegacyIdentity(path);
        if (cursor is not null && !FileIdentities.Same(cursor.FileIdentity, currentIdentity, path))
        {
            var rotated = FindRotated(path, cursor.FileIdentity);
            if (rotated is not null)
            {
                var drained = Read(source, rotated, cursor.FileIdentity, cursor.Offset, events, capacity);
                // The batch filled up while finishing the rotated file: keep pointing at it and continue next poll.
                if (!drained.Finished) return drained.Cursor;
            }
            cursor = null;
        }
        return Read(source, path, currentIdentity, cursor?.Offset ?? 0, events, capacity).Cursor;
    }

    private ReadResult Read(string source, string path, string identity, long offset, List<CollectorEvent> events, int capacity)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        // A file shorter than the cursor was truncated or replaced in place: start it again from the top.
        if (offset > stream.Length) offset = 0;
        var consumed = offset;
        foreach (var line in LogTail.ReadCompleteLines(stream, offset))
        {
            if (events.Count >= capacity) return new ReadResult(new FileCursor(identity, consumed), false);
            var normalized = normalize(source, line.Text);
            if (normalized is not null) events.Add(normalized);
            consumed = line.NextOffset;
        }
        return new ReadResult(new FileCursor(identity, consumed), true);
    }

    private string? FindRotated(string path, string storedIdentity)
    {
        var directory = Path.GetDirectoryName(path);
        if (directory is null || !Directory.Exists(directory)) return null;
        var pattern = $"{Path.GetFileNameWithoutExtension(path)}-*{Path.GetExtension(path)}";
        return Directory.GetFiles(directory, pattern)
            .OrderByDescending(File.GetLastWriteTimeUtc)
            .FirstOrDefault(candidate => FileIdentities.Same(storedIdentity, identityOf(candidate), candidate));
    }

    /// <summary>Used only where the Windows file index can't be read; matches the format earlier versions saved.</summary>
    private static string LegacyIdentity(string path) =>
        $"{File.GetCreationTimeUtc(path).Ticks}:{new FileInfo(path).Length}";
}
