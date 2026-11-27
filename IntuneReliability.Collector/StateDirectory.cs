// SPDX-License-Identifier: Apache-2.0

using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace IntuneReliability.Collector;

/// <summary>
/// The folder that holds the device credential, enrollment token and cursors. The credential uses machine-scoped
/// DPAPI, which any local account could decrypt, so the folder itself must stay readable only by SYSTEM and
/// Administrators. The installer sets that; the service enforces it too, in case the folder is recreated.
/// </summary>
public sealed class StateDirectory(ILogger<StateDirectory> logger)
{
    public static readonly string Path = System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "IntuneReliability", "Collector");

    /// <summary>Creates the folder if needed and resets its permissions. Called once when the service starts.</summary>
    public void EnsureProtected()
    {
        if (!OperatingSystem.IsWindows()) { Directory.CreateDirectory(Path); return; }
        try
        {
            Protect();
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or IOException or InvalidOperationException)
        {
            logger.LogError(exception, "The collector could not restrict its state folder to SYSTEM and Administrators. Reinstall the collector as Administrator.");
        }
    }

    /// <summary>Creates the folder with restricted permissions before a write, if it no longer exists.</summary>
    public void EnsureExists()
    {
        if (!Directory.Exists(Path)) EnsureProtected();
    }

    [SupportedOSPlatform("windows")]
    private static void Protect()
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
        {
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(sid, null),
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }
        var directory = new DirectoryInfo(Path);
        if (directory.Exists) directory.SetAccessControl(security);
        else directory.Create(security);
    }
}
