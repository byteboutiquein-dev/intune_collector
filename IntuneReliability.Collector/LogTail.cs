// SPDX-License-Identifier: Apache-2.0

using System.Text;

namespace IntuneReliability.Collector;

/// <summary>A complete log line and the byte offset just after it, which is where the next read starts.</summary>
public readonly record struct LogLine(string Text, long NextOffset);

/// <summary>
/// Reads newline-terminated lines from a byte offset. A line still being written (no newline yet) is left for the
/// next poll, and the offset after each line is exact, so a cursor never skips or splits a line.
/// </summary>
public static class LogTail
{
    /// <summary>Longer lines are skipped (returned empty) so one malformed line can't grow memory without bound.</summary>
    public const int MaximumLineBytes = 64 * 1024;
    private static readonly byte[] Utf8Bom = [0xEF, 0xBB, 0xBF];

    public static IEnumerable<LogLine> ReadCompleteLines(Stream stream, long offset)
    {
        if (offset == 0 && StartsWithBom(stream)) offset = Utf8Bom.Length;
        stream.Seek(offset, SeekOrigin.Begin);
        var buffer = new byte[8192];
        var line = new MemoryStream();
        var oversized = false;
        var position = offset;
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            for (var index = 0; index < read; index++)
            {
                position++;
                var value = buffer[index];
                if (value != (byte)'\n')
                {
                    if (oversized) continue;
                    if (line.Length >= MaximumLineBytes) { oversized = true; line.SetLength(0); continue; }
                    line.WriteByte(value);
                    continue;
                }
                yield return new LogLine(oversized ? string.Empty : Decode(line), position);
                line.SetLength(0);
                oversized = false;
            }
        }
    }

    private static string Decode(MemoryStream line)
    {
        var bytes = line.GetBuffer();
        var length = (int)line.Length;
        if (length > 0 && bytes[length - 1] == (byte)'\r') length--;
        return Encoding.UTF8.GetString(bytes, 0, length);
    }

    private static bool StartsWithBom(Stream stream)
    {
        if (stream.Length < Utf8Bom.Length) return false;
        stream.Seek(0, SeekOrigin.Begin);
        Span<byte> head = stackalloc byte[3];
        return stream.Read(head) == Utf8Bom.Length && head.SequenceEqual(Utf8Bom);
    }
}
