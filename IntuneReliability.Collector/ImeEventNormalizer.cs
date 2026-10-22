// SPDX-License-Identifier: Apache-2.0

using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace IntuneReliability.Collector;

public sealed partial class ImeEventNormalizer
{
    private const string EmptyGuid = "00000000-0000-0000-0000-000000000000";
    private readonly HashSet<string> installerObservedByApp = new(StringComparer.OrdinalIgnoreCase);
    private readonly object stateLock = new();

    [GeneratedRegex(@"(?i)(?<app>[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})")]
    private static partial Regex AppIdRegex();
    [GeneratedRegex(@"(?i)(?:policy with id:\s*|app with id:\s*|app:\s*|for app\s+|app\s*\(id\s*=\s*)(?<app>[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})")]
    private static partial Regex ContextualAppIdRegex();
    [GeneratedRegex(@"(?i)""ApplicationId""\s*:\s*""(?<app>[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})""")]
    private static partial Regex JsonAppIdRegex();
    [GeneratedRegex(@"(?i)""ImpactingApps""\s*:\s*\[\s*\{[^}]*""AppId""\s*:\s*""(?<app>[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})""")]
    private static partial Regex ImpactingAppIdRegex();
    [GeneratedRegex(@"(?i)(?:exit code|exitCode)[^0-9-]*(?<code>-?\d+)")]
    private static partial Regex ExitCodeRegex();
    [GeneratedRegex("time=\"(?<time>[0-9]{1,2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]+)?)\"\\s+date=\"(?<date>[0-9]{1,2}-[0-9]{1,2}-[0-9]{4})\"", RegexOptions.IgnoreCase)]
    private static partial Regex SourceTimestampRegex();

    public CollectorEvent? Normalize(string sourceType, string line)
    {
        var normalized = line.ToLowerInvariant();
        var applicationId = ExtractApplicationId(line);
        var installerObserved = applicationId is not null && InstallerObserved(applicationId);
        var mapping = normalized switch
        {
            var text when text.Contains("grsmanager") && text.Contains("app with id:") && text.Contains("is not expired") => ("ENFORCEMENT_DEFERRED_GRS", "DEFERRED", "warning"),
            var text when text.Contains("reevaluation") && (text.Contains("not expired") || text.Contains("not due")) => ("REEVALUATION_NOT_DUE", "RETRY_WAIT", "warning"),
            var text when text.Contains("intune management extension") && text.Contains("started") => ("IME_STARTED", "UNKNOWN", "info"),
            var text when text.Contains("check-in") && (text.Contains("started") || text.Contains("completed") || text.Contains("received")) => ("IME_CHECKIN", "UNKNOWN", "info"),
            var text when text.Contains("policy") && (text.Contains("received") || text.Contains("downloaded") || text.Contains("retrieved")) => ("POLICY_RECEIVED", "TARGETING", "info"),
            var text when (text.Contains("not targeted") || text.Contains("targeting excluded")) => ("APP_NOT_TARGETED", "TARGETING", "info"),
            var text when (text.Contains("app") && text.Contains("targeted")) || text.Contains("targeting included") => ("APP_TARGETED", "TARGETING", "info"),
            var text when text.Contains("retry") && (text.Contains("scheduled") || text.Contains("after") || text.Contains(" at ")) => ("RETRY_SCHEDULED", "RETRY_WAIT", "warning"),
            var text when (text.Contains("skipped") || text.Contains("skipping")) && (text.Contains("processing") || text.Contains("action") || text.Contains("enforcement")) => ("APP_ACTION_SKIPPED", "DEFERRED", "info"),
            var text when text.Contains("detectionactionhandler") && text.Contains("detection for policy with id:") && text.Contains("detection state: notdetected") && installerObserved => ("DETECTION_POST_FAILED", "POST_INSTALL_DETECTION", "error"),
            var text when text.Contains("detectionactionhandler") && text.Contains("detection for policy with id:") && text.Contains("detection state: notdetected") => ("DETECTION_PRE_ABSENT", "PRE_INSTALL_DETECTION", "info"),
            var text when text.Contains("detectionactionhandler") && text.Contains("detection for policy with id:") && text.Contains("detection state: detected") && installerObserved => ("DETECTION_POST_PASSED", "POST_INSTALL_DETECTION", "info"),
            var text when text.Contains("detectionactionhandler") && text.Contains("detection for policy with id:") && text.Contains("detection state: detected") => ("DETECTION_PRE_PRESENT", "PRE_INSTALL_DETECTION", "info"),
            var text when text.Contains("reportingmanager") && text.Contains("detection state for app with id:") && text.Contains("\"newvalue\":\"installed\"") => ("DETECTION_POST_PASSED", "POST_INSTALL_DETECTION", "info"),
            var text when text.Contains("applicabilityactionhandler") && text.Contains("applicability check for policy with id:") && text.Contains("applicability state: applicable") => ("APPLICABILITY_PASSED", "APPLICABILITY", "info"),
            var text when text.Contains("applicabilityactionhandler") && text.Contains("applicability check for policy with id:") && (text.Contains("notapplicable") || text.Contains("action status: failed")) => ("APPLICABILITY_FAILED", "APPLICABILITY", "warning"),
            var text when text.Contains("requirement") && (text.Contains("failed") || text.Contains("not met") || text.Contains("not satisfied")) => ("REQUIREMENT_FAILED", "REQUIREMENT", "warning"),
            var text when text.Contains("requirement") && (text.Contains("passed") || text.Contains(" met") || text.Contains("satisfied")) => ("REQUIREMENT_PASSED", "REQUIREMENT", "info"),
            var text when IsStructuredDependencyFailure(text) => ("DEPENDENCY_FAILED", "DEPENDENCY", "warning"),
            var text when (text.Contains("dependency") || text.Contains("dependencies")) && (text.Contains("failed") || text.Contains("not met") || text.Contains("missing")) => ("DEPENDENCY_FAILED", "DEPENDENCY", "warning"),
            var text when (text.Contains("dependency") || text.Contains("dependencies")) && (text.Contains("passed") || text.Contains("satisfied") || text.Contains("installed")) => ("DEPENDENCY_PASSED", "DEPENDENCY", "info"),
            var text when text.Contains("downloadactionhandler") && text.Contains("handler invoked for policy with id:") => ("CONTENT_DOWNLOAD_STARTED", "CONTENT", "info"),
            var text when text.Contains("content cache miss for app") && text.Contains("start downloading") => ("CONTENT_DOWNLOAD_STARTED", "CONTENT", "info"),
            var text when text.Contains("reportingmanager") && text.Contains("download state for app with id:") && text.Contains("inprogressdownloadcompleted") => ("CONTENT_DOWNLOAD_COMPLETED", "CONTENT", "info"),
            var text when text.Contains("reportingmanager") && text.Contains("download state for app with id:") && text.Contains("fail") => ("CONTENT_DOWNLOAD_FAILED", "CONTENT", "error"),
            var text when text.Contains("executionactionhandler") && text.Contains("handler invoked with execution type:") && text.Contains("policy with id:") => ("INSTALLER_STARTED", "INSTALLER", "info"),
            var text when text.Contains("reportingmanager") && text.Contains("execution state for app with id:") && text.Contains("\"newvalue\":\"success\"") => ("INSTALLER_SUCCEEDED", "INSTALLER", "info"),
            var text when text.Contains("reportingmanager") && text.Contains("execution state for app with id:") && (text.Contains("\"newvalue\":\"error\"") || text.Contains("\"newvalue\":\"failed\"")) => ("INSTALLER_FAILED", "INSTALLER", "error"),
            var text when text.Contains("statusservicereportsstore") && text.Contains("saved appinstallstatusreport") && text.Contains(" for app ") => ("REPORTING_SUCCEEDED", "REPORTING", "info"),
            var text when text.Contains("reportingmanager") && (text.Contains("failed to send") || text.Contains("failed to report")) => ("REPORTING_FAILED", "REPORTING", "error"),
            var text when (text.Contains("health") || text.Contains("remediation")) && (text.Contains("failed") || text.Contains("failure") || text.Contains("unhealthy") || text.Contains("critical")) => ("CLIENT_HEALTH_FAILURE", "CLIENT_HEALTH", "error"),
            var text when (text.Contains("health") || text.Contains("remediation")) && (text.Contains("warning") || text.Contains("degraded") || text.Contains("issue")) => ("CLIENT_HEALTH_WARNING", "CLIENT_HEALTH", "warning"),
            var text when text.Contains("grs") && text.Contains("defer") => ("ENFORCEMENT_DEFERRED_GRS", "DEFERRED", "warning"),
            var text when text.Contains("post") && text.Contains("detection") && text.Contains("failed") => ("DETECTION_POST_FAILED", "POST_INSTALL_DETECTION", "error"),
            var text when text.Contains("post") && text.Contains("detection") && text.Contains("success") => ("DETECTION_POST_PASSED", "POST_INSTALL_DETECTION", "info"),
            var text when text.Contains("installer") && text.Contains("started") => ("INSTALLER_STARTED", "INSTALLER", "info"),
            var text when text.Contains("exit code") => ("INSTALLER_EXITED", "INSTALLER", "info"),
            var text when (text.Contains("installer") || text.Contains("installation")) && (text.Contains("completed") || text.Contains("succeeded") || text.Contains("successful")) => ("INSTALLER_SUCCEEDED", "INSTALLER", "info"),
            var text when (text.Contains("installer") || text.Contains("installation")) && (text.Contains("failed") || text.Contains("failure") || text.Contains("error")) => ("INSTALLER_FAILED", "INSTALLER", "error"),
            var text when text.Contains("content") && text.Contains("download") && text.Contains("failed") => ("CONTENT_DOWNLOAD_FAILED", "CONTENT", "error"),
            _ => default
        };
        if (mapping == default) return null;
        if (sourceType.Equals("client_health_log", StringComparison.OrdinalIgnoreCase)
            && mapping.Item1 is "CLIENT_HEALTH_WARNING" or "CLIENT_HEALTH_FAILURE")
        {
            // ClientHealth GUIDs identify health/remediation operations, not Win32 applications.
            applicationId = null;
        }
        if (applicationId is not null)
        {
            if (mapping.Item1 is "APPLICABILITY_PASSED" or "APPLICABILITY_FAILED" or "ENFORCEMENT_DEFERRED_GRS") ForgetInstaller(applicationId);
            if (mapping.Item1 is "INSTALLER_STARTED" or "INSTALLER_EXITED" or "INSTALLER_SUCCEEDED" or "INSTALLER_FAILED") RememberInstaller(applicationId);
            if (mapping.Item1 is "DETECTION_POST_PASSED" or "DETECTION_POST_FAILED") ForgetInstaller(applicationId);
        }
        var sourceHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(line))).ToLowerInvariant();
        var codeMatch = ExitCodeRegex().Match(line);
        var timestampMatch = SourceTimestampRegex().Match(line);
        var attributes = new Dictionary<string, object?>();
        if (codeMatch.Success && int.TryParse(codeMatch.Groups["code"].Value, out var code)) attributes["exitCode"] = code;
        if (mapping.Item1 == "ENFORCEMENT_DEFERRED_GRS") attributes["registryStatePresent"] = true;
        if (mapping.Item1 == "DEPENDENCY_FAILED" && IsStructuredDependencyFailure(normalized))
        {
            attributes["enforcementState"] = 6005;
            attributes["relationshipType"] = 3;
            attributes["conflictReason"] = 2;
            var impactingApp = ImpactingAppIdRegex().Match(line);
            if (impactingApp.Success) attributes["impactingApplicationId"] = impactingApp.Groups["app"].Value.ToLowerInvariant();
        }
        var sourceTimestamp = timestampMatch.Success
            ? $"{timestampMatch.Groups["date"].Value} {timestampMatch.Groups["time"].Value}"
            : null;
        var fingerprintMaterial = $"{sourceType}|{mapping.Item1}|{applicationId}|{sourceHash}";
        var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fingerprintMaterial))).ToLowerInvariant();
        return new CollectorEvent(
            fingerprint, mapping.Item1, mapping.Item2, mapping.Item3,
            applicationId, null, sourceTimestamp, sourceType, sourceHash,
            $"Normalized {mapping.Item1} endpoint evidence.", attributes);
    }

    private bool InstallerObserved(string applicationId)
    {
        lock (stateLock) return installerObservedByApp.Contains(applicationId);
    }

    private void RememberInstaller(string applicationId)
    {
        lock (stateLock) installerObservedByApp.Add(applicationId);
    }

    private void ForgetInstaller(string applicationId)
    {
        lock (stateLock) installerObservedByApp.Remove(applicationId);
    }

    private static bool IsStructuredDependencyFailure(string text)
    {
        return text.Contains("[reportingmanager]")
            && text.Contains("sending status to company portal based on report:")
            && text.Contains("\"reportingimpact\":{")
            && text.Contains("\"impactingapps\":[{")
            && text.Contains("\"relationshiptype\":3")
            && text.Contains("\"conflictreason\":2")
            && text.Contains("\"enforcementstate\":6005");
    }

    private static string? ExtractApplicationId(string line)
    {
        foreach (var regex in new[] { ContextualAppIdRegex(), JsonAppIdRegex() })
        {
            var contextual = regex.Match(line);
            if (contextual.Success) return contextual.Groups["app"].Value.ToLowerInvariant();
        }

        return AppIdRegex().Matches(line)
            .Select(match => match.Groups["app"].Value.ToLowerInvariant())
            .FirstOrDefault(value => value != EmptyGuid);
    }
}
