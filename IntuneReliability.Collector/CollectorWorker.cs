// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Reflection;
using Microsoft.Extensions.Options;

namespace IntuneReliability.Collector;

public sealed class CollectorWorker(
    IOptions<CollectorOptions> options,
    StateDirectory state,
    CredentialStore credentials,
    CursorStore cursorStore,
    LogCollector collector,
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

    private static readonly TimeSpan TokenCheckInterval = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan FirstEnrollmentRetry = TimeSpan.FromSeconds(30);

    private TimeSpan PollInterval => TimeSpan.FromSeconds(Math.Clamp(options.Value.PollSeconds, 15, 3600));

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        state.EnsureProtected();
        var credential = credentials.Load() ?? await EnrollAsync(stoppingToken);
        if (credential is null) return;

        var failures = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            var delay = PollInterval;
            try
            {
                await CollectOnceAsync(credential, stoppingToken);
                failures = 0;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (HttpRequestException exception) when (exception.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                // A revoked or rejected credential won't start working on its own, so check rarely until it's replaced.
                failures++;
                delay = Backoff.Ceiling;
                logger.LogError("SentVora rejected this device's credential (HTTP {Status}); it may have been revoked. Create a new enrollment and run Reenroll-Collector.ps1. Uploads are paused and retried every {Minutes} minutes.", (int)exception.StatusCode!.Value, (int)delay.TotalMinutes);
            }
            catch (Exception exception)
            {
                failures++;
                delay = Backoff.Delay(failures, PollInterval);
                logger.LogWarning(exception, "Collector upload failed; cursors were not advanced. Retrying in {Seconds} seconds.", (int)delay.TotalSeconds);
            }
            await Task.Delay(delay, stoppingToken);
        }
    }

    /// <summary>
    /// Waits for an enrollment token and exchanges it for a credential. A missing token is checked for again every
    /// minute; an unreachable server is retried with growing delays; a refused token waits for a replacement.
    /// The service keeps running throughout, so it never stops quietly before it is enrolled.
    /// </summary>
    private async Task<string?> EnrollAsync(CancellationToken stoppingToken)
    {
        var failures = 0;
        var reportedMissing = false;
        while (!stoppingToken.IsCancellationRequested)
        {
            var token = ReadEnrollmentToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                if (!reportedMissing) logger.LogWarning("Collector is not enrolled yet. It checks for an enrollment token every {Seconds} seconds.", (int)TokenCheckInterval.TotalSeconds);
                reportedMissing = true;
                await Task.Delay(TokenCheckInterval, stoppingToken);
                continue;
            }

            TimeSpan delay;
            try
            {
                var credential = await api.ClaimAsync(token, stoppingToken);
                credentials.Save(credential);
                DeleteEnrollmentTokenFile();
                logger.LogInformation("Collector enrollment completed and the one-time token was removed.");
                return credential;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return null;
            }
            catch (HttpRequestException exception) when (IsRefusal(exception.StatusCode))
            {
                failures++;
                delay = Backoff.Ceiling;
                logger.LogError("SentVora refused the enrollment token (HTTP {Status}); it may have expired or already been used. Create a new enrollment and replace the token. Checking again in {Minutes} minutes.", (int)exception.StatusCode!.Value, (int)delay.TotalMinutes);
            }
            catch (Exception exception)
            {
                failures++;
                delay = Backoff.Delay(failures, FirstEnrollmentRetry);
                logger.LogWarning(exception, "Enrollment could not reach SentVora. Retrying in {Seconds} seconds.", (int)delay.TotalSeconds);
            }
            await Task.Delay(delay, stoppingToken);
        }
        return null;
    }

    /// <summary>A 4xx answer means the token itself was refused; timeouts and rate limits are worth retrying sooner.</summary>
    public static bool IsRefusal(HttpStatusCode? status) =>
        status is { } code && (int)code is >= 400 and < 500 && code is not HttpStatusCode.RequestTimeout and not HttpStatusCode.TooManyRequests;

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
        var previous = cursorStore.Load();
        var next = new Dictionary<string, FileCursor>(previous);
        var events = new List<CollectorEvent>();
        var capacity = Math.Clamp(options.Value.MaximumEventsPerBatch, 1, 500);
        foreach (var (source, filePath) in Sources)
        {
            var cursor = collector.Collect(source, filePath, previous.GetValueOrDefault(source), events, capacity);
            if (cursor is not null) next[source] = cursor;
        }
        if (events.Count == 0)
        {
            // Lines were read but none were evidence: save the cursors so they aren't read again.
            if (!CursorsEqual(previous, next)) cursorStore.Save(next);
            return;
        }
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "2.10.0";
        var idempotencyKey = $"collector:{Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(string.Join('|', events.Select(item => item.EventFingerprint))))).ToLowerInvariant()}";
        await api.UploadAsync(credential, new CollectorBatch(idempotencyKey, version, events, next), cancellationToken);
        cursorStore.Save(next);
    }

    private static bool CursorsEqual(IReadOnlyDictionary<string, FileCursor> left, IReadOnlyDictionary<string, FileCursor> right) =>
        left.Count == right.Count && left.All(pair => right.TryGetValue(pair.Key, out var other) && other == pair.Value);
}
