// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Text;
using IntuneReliability.Collector;
using Xunit;

namespace IntuneReliability.Collector.Tests;

public sealed class LogTailTests
{
    private static MemoryStream Stream(string text, bool bom = false) =>
        new((bom ? Encoding.UTF8.GetPreamble() : []).Concat(Encoding.UTF8.GetBytes(text)).ToArray());

    [Fact]
    public void LeavesAHalfWrittenLineForTheNextRead()
    {
        var lines = LogTail.ReadCompleteLines(Stream("one\r\ntwo\nthr"), 0).ToArray();
        Assert.Equal(["one", "two"], lines.Select(line => line.Text));
        Assert.Equal(9, lines[^1].NextOffset);
    }

    [Fact]
    public void ResumesExactlyWhereTheLastLineEnded()
    {
        var stream = Stream("one\ntwo\nthree\n");
        var first = LogTail.ReadCompleteLines(stream, 0).First();
        Assert.Equal(["two", "three"], LogTail.ReadCompleteLines(stream, first.NextOffset).Select(line => line.Text));
    }

    [Fact]
    public void SkipsTheByteOrderMarkAndCountsItInTheOffset()
    {
        var lines = LogTail.ReadCompleteLines(Stream("one\n", bom: true), 0).ToArray();
        Assert.Equal("one", lines[0].Text);
        Assert.Equal(7, lines[0].NextOffset);
    }

    [Fact]
    public void ReturnsAnOversizedLineEmptyButStillMovesPastIt()
    {
        var huge = new string('x', LogTail.MaximumLineBytes + 10);
        var lines = LogTail.ReadCompleteLines(Stream($"{huge}\nnext\n"), 0).ToArray();
        Assert.Equal(["", "next"], lines.Select(line => line.Text));
    }
}

public sealed class LogCollectorTests : IDisposable
{
    private readonly string directory = Directory.CreateTempSubdirectory("collector-tests-").FullName;
    private readonly Dictionary<string, string> identities = new();

    public void Dispose() => Directory.Delete(directory, true);

    /// <summary>Lines starting with "E" are evidence; everything else is ignored, like ordinary IME noise.</summary>
    private LogCollector Collector() => new(
        (source, line) => line.StartsWith('E') ? new CollectorEvent(line, "test", "test", "info", null, null, null, source, line, line, new Dictionary<string, object?>()) : null,
        path => identities.GetValueOrDefault(path));

    private string Log(string name, string text, string identity)
    {
        var path = Path.Combine(directory, name);
        File.WriteAllText(path, text);
        identities[path] = identity;
        return path;
    }

    [Fact]
    public void AFullBatchStopsBeforeTheNextLineInsteadOfSkippingIt()
    {
        var path = Log("AppWorkload.log", "E1\nnoise\nE2\nE3\nE4\n", "file:a");
        var collector = Collector();
        var events = new List<CollectorEvent>();
        var cursor = collector.Collect("app", path, null, events, capacity: 2);
        Assert.Equal(["E1", "E2"], events.Select(item => item.EventFingerprint));

        var rest = new List<CollectorEvent>();
        collector.Collect("app", path, cursor, rest, capacity: 10);
        Assert.Equal(["E3", "E4"], rest.Select(item => item.EventFingerprint));
    }

    [Fact]
    public void FinishesARotatedLogBeforeStartingTheNewOne()
    {
        var path = Log("AppWorkload.log", "E1\n", "file:old");
        var collector = Collector();
        var cursor = collector.Collect("app", path, null, [], capacity: 10);

        // IME writes one more line, then renames the log and starts a new file under the old name.
        File.AppendAllText(path, "E2\n");
        var rotated = Path.Combine(directory, "AppWorkload-20261127-101010.log");
        File.Move(path, rotated);
        identities.Remove(path);
        identities[rotated] = "file:old";
        Log("AppWorkload.log", "E3\n", "file:new");

        var events = new List<CollectorEvent>();
        var next = collector.Collect("app", path, cursor, events, capacity: 10);
        Assert.Equal(["E2", "E3"], events.Select(item => item.EventFingerprint));
        Assert.Equal("file:new", next!.FileIdentity);
    }

    [Fact]
    public void KeepsDrainingTheRotatedLogWhenTheBatchFillsUp()
    {
        var path = Log("AppWorkload.log", "", "file:old");
        var collector = Collector();
        var cursor = collector.Collect("app", path, null, [], capacity: 10);
        File.AppendAllText(path, "E1\nE2\nE3\n");
        var rotated = Path.Combine(directory, "AppWorkload-20261127-101010.log");
        File.Move(path, rotated);
        identities.Remove(path);
        identities[rotated] = "file:old";
        Log("AppWorkload.log", "E4\n", "file:new");

        var first = new List<CollectorEvent>();
        cursor = collector.Collect("app", path, cursor, first, capacity: 2);
        Assert.Equal(["E1", "E2"], first.Select(item => item.EventFingerprint));
        Assert.Equal("file:old", cursor!.FileIdentity);

        var second = new List<CollectorEvent>();
        collector.Collect("app", path, cursor, second, capacity: 10);
        Assert.Equal(["E3", "E4"], second.Select(item => item.EventFingerprint));
    }

    [Fact]
    public void StartsAgainWhenTheFileWasTruncatedInPlace()
    {
        var path = Log("AppWorkload.log", "E1\nE2\n", "file:a");
        var collector = Collector();
        var cursor = collector.Collect("app", path, null, [], capacity: 10);
        File.WriteAllText(path, "E3\n");
        var events = new List<CollectorEvent>();
        collector.Collect("app", path, cursor, events, capacity: 10);
        Assert.Equal(["E3"], events.Select(item => item.EventFingerprint));
    }
}

public sealed class RetryTests
{
    [Fact]
    public void DelaysDoubleUpToFifteenMinutes()
    {
        var start = TimeSpan.FromSeconds(30);
        Assert.Equal(start, Backoff.Delay(1, start));
        Assert.Equal(TimeSpan.FromSeconds(60), Backoff.Delay(2, start));
        Assert.Equal(TimeSpan.FromSeconds(120), Backoff.Delay(3, start));
        Assert.Equal(Backoff.Ceiling, Backoff.Delay(50, start));
    }

    [Fact]
    public void OnlyA4xxRefusalStopsQuickRetries()
    {
        Assert.True(CollectorWorker.IsRefusal(HttpStatusCode.Gone));
        Assert.True(CollectorWorker.IsRefusal(HttpStatusCode.Unauthorized));
        Assert.False(CollectorWorker.IsRefusal(HttpStatusCode.TooManyRequests));
        Assert.False(CollectorWorker.IsRefusal(HttpStatusCode.RequestTimeout));
        Assert.False(CollectorWorker.IsRefusal(HttpStatusCode.BadGateway));
        Assert.False(CollectorWorker.IsRefusal(null));
    }
}
