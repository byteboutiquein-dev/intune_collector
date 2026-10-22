// SPDX-License-Identifier: Apache-2.0

using IntuneReliability.Collector;
using System.Text.Json;
using Xunit;

namespace IntuneReliability.Collector.Tests;

public sealed class ImeEventNormalizerTests
{
    private readonly ImeEventNormalizer normalizer = new();

    private sealed record ContractExpectation(string EventType, string LifecycleStage);
    private sealed record ContractCase(string Name, string SourceType, string[] Lines, ContractExpectation[] Expected);

    [Fact]
    public void SatisfiesSharedArchiveAndCollectorContract()
    {
        var cases = JsonSerializer.Deserialize<ContractCase[]>(
            File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "parser-contract.json")),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

        Assert.NotNull(cases);
        foreach (var contract in cases!)
        {
            var contractNormalizer = new ImeEventNormalizer();
            var actual = contract.Lines
                .Select(line => contractNormalizer.Normalize(contract.SourceType, line))
                .Where(result => result is not null)
                .Select(result => new ContractExpectation(result!.EventType, result.LifecycleStage))
                .ToArray();
            Assert.Equal(contract.Expected, actual);
        }
    }

    [Fact]
    public void NormalizesInstallerExitAndPreservesOnlyBoundedFields()
    {
        var appId = "5bb8f99b-dce6-4eb9-acd4-022c4099e739";
        var result = normalizer.Normalize(
            "app_workload_log",
            $"Application {appId} installer returned exit code 1603 for user@example.com");

        Assert.NotNull(result);
        Assert.Equal("INSTALLER_EXITED", result.EventType);
        Assert.Equal("INSTALLER", result.LifecycleStage);
        Assert.Equal(appId, result.ImeApplicationId);
        Assert.Equal(1603, result.Attributes["exitCode"]);
        Assert.DoesNotContain("user@example.com", result.Summary);
        Assert.Matches("^[0-9a-f]{64}$", result.EventFingerprint);
        Assert.Matches("^[0-9a-f]{64}$", result.SourceRecordHash);
    }

    [Theory]
    [InlineData("GRS will defer enforcement", "ENFORCEMENT_DEFERRED_GRS", "DEFERRED")]
    [InlineData("Post detection failed", "DETECTION_POST_FAILED", "POST_INSTALL_DETECTION")]
    [InlineData("Post detection success", "DETECTION_POST_PASSED", "POST_INSTALL_DETECTION")]
    [InlineData("Installer started", "INSTALLER_STARTED", "INSTALLER")]
    [InlineData("Content download failed", "CONTENT_DOWNLOAD_FAILED", "CONTENT")]
    public void MapsAllowListedLifecycleEvidence(string line, string eventType, string stage)
    {
        var result = normalizer.Normalize("app_workload_log", line);

        Assert.NotNull(result);
        Assert.Equal(eventType, result.EventType);
        Assert.Equal(stage, result.LifecycleStage);
    }

    [Fact]
    public void IgnoresUnsupportedRawLogLines()
    {
        Assert.Null(normalizer.Normalize("app_workload_log", "Unrelated verbose endpoint text"));
    }

    [Theory]
    [InlineData("Client health remediation failed for operation 0d650fd8-8272-48a8-a7bf-b2380e0e3256", "CLIENT_HEALTH_FAILURE")]
    [InlineData("Client health warning for operation 8f9666f6-cb01-4ed4-b1c9-f0635b99268e", "CLIENT_HEALTH_WARNING")]
    public void KeepsClientHealthEvidenceDeviceScoped(string line, string eventType)
    {
        var result = normalizer.Normalize("client_health_log", line);

        Assert.NotNull(result);
        Assert.Equal(eventType, result.EventType);
        Assert.Equal("CLIENT_HEALTH", result.LifecycleStage);
        Assert.Null(result.ImeApplicationId);
    }

    [Fact]
    public void DoesNotMisclassifyGrsHoldAsReevaluationInterval()
    {
        var result = normalizer.Normalize(
            "app_workload_log",
            "[Win32App][GRSManager] App with id: 5bb8f99b-dce6-4eb9-acd4-022c4099e739 is not expired");

        Assert.NotNull(result);
        Assert.Equal("ENFORCEMENT_DEFERRED_GRS", result.EventType);
        Assert.Equal("DEFERRED", result.LifecycleStage);
    }

    [Fact]
    public void ProducesStableFingerprintsForIdempotentDelivery()
    {
        const string line = "Installer started for 5bb8f99b-dce6-4eb9-acd4-022c4099e739";

        var first = normalizer.Normalize("app_workload_log", line);
        var second = normalizer.Normalize("app_workload_log", line);

        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.Equal(first.EventFingerprint, second.EventFingerprint);
        Assert.Equal(first.SourceRecordHash, second.SourceRecordHash);
    }

    [Theory]
    [InlineData("[Win32App][GRSManager] App with id: 5bb8f99b-dce6-4eb9-acd4-022c4099e739 is not expired.", "ENFORCEMENT_DEFERRED_GRS", "DEFERRED")]
    [InlineData("[Win32App][DetectionActionHandler] Detection for policy with id: 5bb8f99b-dce6-4eb9-acd4-022c4099e739 resulted in action status: Success and detection state: NotDetected.", "DETECTION_PRE_ABSENT", "PRE_INSTALL_DETECTION")]
    [InlineData("[Win32App][DetectionActionHandler] Detection for policy with id: 5bb8f99b-dce6-4eb9-acd4-022c4099e739 resulted in action status: Success and detection state: Detected.", "DETECTION_PRE_PRESENT", "PRE_INSTALL_DETECTION")]
    [InlineData("[Win32App][ApplicabilityActionHandler] Applicability check for policy with id: 5bb8f99b-dce6-4eb9-acd4-022c4099e739 resulted in action status: Success and applicability state: Applicable.", "APPLICABILITY_PASSED", "APPLICABILITY")]
    [InlineData("[Win32App][DownloadActionHandler] Handler invoked for policy with id: 5bb8f99b-dce6-4eb9-acd4-022c4099e739 and version: 1", "CONTENT_DOWNLOAD_STARTED", "CONTENT")]
    [InlineData("[Win32App][ReportingManager] Download state for app with id: 5bb8f99b-dce6-4eb9-acd4-022c4099e739 has been updated. Report delta: {\"EnforcementState\":{\"OldValue\":\"InProgress\",\"NewValue\":\"InProgressDownloadCompleted\"}}", "CONTENT_DOWNLOAD_COMPLETED", "CONTENT")]
    [InlineData("[Win32App][ExecutionActionHandler] Handler invoked with execution type: Install for policy with id: 5bb8f99b-dce6-4eb9-acd4-022c4099e739 and version: 1.", "INSTALLER_STARTED", "INSTALLER")]
    [InlineData("[Win32App][ReportingManager] Execution state for app with id: 5bb8f99b-dce6-4eb9-acd4-022c4099e739 has been updated. Report delta: {\"EnforcementState\":{\"OldValue\":\"InProgressDownloadCompleted\",\"NewValue\":\"Success\"}}", "INSTALLER_SUCCEEDED", "INSTALLER")]
    public void MapsCapturedImeLifecycleLines(string line, string eventType, string stage)
    {
        var result = normalizer.Normalize("app_workload_log", line);

        Assert.NotNull(result);
        Assert.Equal(eventType, result.EventType);
        Assert.Equal(stage, result.LifecycleStage);
        Assert.Equal("5bb8f99b-dce6-4eb9-acd4-022c4099e739", result.ImeApplicationId);
    }

    [Fact]
    public void PrefersApplicationIdOverTheDeviceUserPlaceholderAndCapturesSourceTime()
    {
        const string line = "<![LOG[[Win32App][StatusServiceReportsStore] Saved AppInstallStatusReport for user 00000000-0000-0000-0000-000000000000 for app 5bb8f99b-dce6-4eb9-acd4-022c4099e739 in the StatusServiceReports registry.]LOG]!><time=\"20:03:37.8459021\" date=\"9-27-2026\" component=\"AppWorkload\">";

        var result = normalizer.Normalize("app_workload_log", line);

        Assert.NotNull(result);
        Assert.Equal("REPORTING_SUCCEEDED", result.EventType);
        Assert.Equal("5bb8f99b-dce6-4eb9-acd4-022c4099e739", result.ImeApplicationId);
        Assert.Equal("9-27-2026 20:03:37.8459021", result.SourceTimestamp);
    }

    [Fact]
    public void MapsCapturedReportingImpactToTheParentDependencyFailure()
    {
        const string parentId = "11111111-2222-4333-8444-555555555555";
        const string childId = "66666666-7777-4888-8999-aaaaaaaaaaaa";
        var line = "<![LOG[[Win32App][ReportingManager] Sending status to company portal based on report: {\"ApplicationId\":\""
            + parentId
            + "\",\"ResultantAppState\":3,\"ReportingImpact\":{\"DesiredState\":3,\"Classification\":1,\"ConflictReason\":2,\"ImpactingApps\":[{\"AppId\":\""
            + childId
            + "\",\"RelationshipType\":3,\"RelativeType\":1,\"DesiredState\":3}]},\"EnforcementState\":6005}]LOG]!><time=\"11:24:40.7303624\" date=\"10-18-2026\" component=\"AppWorkload\">";

        var result = normalizer.Normalize("app_workload_log", line);

        Assert.NotNull(result);
        Assert.Equal("DEPENDENCY_FAILED", result.EventType);
        Assert.Equal("DEPENDENCY", result.LifecycleStage);
        Assert.Equal(parentId, result.ImeApplicationId);
        Assert.Equal(childId, result.Attributes["impactingApplicationId"]);
        Assert.Equal(6005, result.Attributes["enforcementState"]);
    }

    [Theory]
    [InlineData("[Win32App][ReportingManager] Sending status to company portal based on report: {\"ApplicationId\":\"11111111-2222-4333-8444-555555555555\",\"ReportingImpact\":null,\"EnforcementState\":6005}")]
    [InlineData("[Win32App][ReportingManager] Sending status to company portal based on report: {\"ApplicationId\":\"11111111-2222-4333-8444-555555555555\",\"ReportingImpact\":{\"ImpactingApps\":[{\"RelationshipType\":2}]},\"EnforcementState\":6005}")]
    public void DoesNotInferDependencyFailureFromIncompleteReportingImpact(string line)
    {
        Assert.Null(normalizer.Normalize("app_workload_log", line));
    }
}
