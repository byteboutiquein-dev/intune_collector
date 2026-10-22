// SPDX-License-Identifier: Apache-2.0

using System.Reflection;
using Microsoft.Extensions.Options;

namespace IntuneReliability.Collector;

public sealed class CollectorWorker(
    IOptions<CollectorOptions> options,
    CredentialStore credentials,
    CursorStore cursorStore,
    ImeEventNormalizer normalizer,
    CollectorApiClient api,
    ILogger<CollectorWorker> logger) : BackgroundService
{
    private static readonly IReadOnlyDictionary<string, string> Sources = new Dictionary<string, string>
    {
        ["app_workload_log"] = @"C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AppWorkload.log",
        ["app_action_processor_log"] = @"C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AppActionProcessor.log",
        ["agent_executor_log"] = @"C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AgentExecutor.log",
        ["client_health_log"] = @"C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\ClientHealth.log",
        ["intune_management_extension_log"] = @"C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log"
    };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var credential = credentials.Load();
        if (credential is null)
        {
            var enrollmentToken = ReadEnrollmentToken();
            if (string.IsNullOrWhiteSpace(enrollmentToken))
            {
                logger.LogWarning("Collector is not enrolled; endpoint evidence collection remains inactive.");
                return;
            }
            credential = await api.ClaimAsync(enrollmentToken, stoppingToken);
            credentials.Save(credential);
            DeleteEnrollmentTokenFile();
            logger.LogInformation("Collector enrollment completed and the one-time token was removed.");
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try { await CollectOnceAsync(credential, stoppingToken); }
            catch (Exception exception) { logger.LogWarning(exception, "Collector upload failed; cursors were not advanced."); }
            await Task.Delay(TimeSpan.FromSeconds(Math.Clamp(options.Value.PollSeconds, 15, 3600)), stoppingToken);
        }
    }

    private string? ReadEnrollmentToken()
    {
        var environmentToken = Environment.GetEnvironmentVariable("IRL_COLLECTOR_ENROLLMENT_TOKEN");
        if (!string.IsNullOrWhiteSpace(environmentToken)) return environmentToken.Trim();
        var path = options.Value.EnrollmentTokenPath;
        return File.Exists(path) ? File.ReadAllText(path).Trim() : null;
    }

    private void DeleteEnrollmentTokenFile()
    {
        var path = options.Value.EnrollmentTokenPath;
        if (File.Exists(path)) File.Delete(path);
    }

    private async Task CollectOnceAsync(string credential, CancellationToken cancellationToken)
    {
        var previous = new Dictionary<string, FileCursor>(cursorStore.Load());
        var next = new Dictionary<string, FileCursor>(previous);
        var events = new List<CollectorEvent>();
        foreach (var (source, filePath) in Sources)
        {
            if (!File.Exists(filePath)) continue;
            var identity = $"{new FileInfo(filePath).CreationTimeUtc.Ticks}:{new FileInfo(filePath).Length}";
            var cursor = previous.GetValueOrDefault(source);
            var offset = cursor is not null && cursor.FileIdentity.Split(':')[0] == identity.Split(':')[0] ? cursor.Offset : 0;
            await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (offset > stream.Length) offset = 0;
            stream.Seek(offset, SeekOrigin.Begin);
            using var reader = new StreamReader(stream);
            while (!reader.EndOfStream && events.Count < Math.Clamp(options.Value.MaximumEventsPerBatch, 1, 500))
            {
                var line = await reader.ReadLineAsync(cancellationToken);
                if (line is null) break;
                var normalized = normalizer.Normalize(source, line);
                if (normalized is not null) events.Add(normalized);
            }
            next[source] = new FileCursor(identity, stream.Position);
        }
        if (events.Count == 0) return;
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "2.10.0";
        var idempotencyKey = $"collector:{Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(string.Join('|', events.Select(item => item.EventFingerprint))))).ToLowerInvariant()}";
        await api.UploadAsync(credential, new CollectorBatch(idempotencyKey, version, events, next), cancellationToken);
        cursorStore.Save(next);
    }
}
