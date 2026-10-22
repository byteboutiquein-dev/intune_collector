// SPDX-License-Identifier: Apache-2.0

using System.Security.Cryptography;
using System.Text;

namespace IntuneReliability.Collector;

public sealed class CredentialStore
{
    private static readonly string DirectoryPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "IntuneReliability", "Collector");
    private static readonly string CredentialPath = Path.Combine(DirectoryPath, "credential.bin");

    public string? Load()
    {
        if (!File.Exists(CredentialPath)) return null;
        var protectedBytes = File.ReadAllBytes(CredentialPath);
        var clear = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.LocalMachine);
        return Encoding.UTF8.GetString(clear);
    }

    public void Save(string credential)
    {
        Directory.CreateDirectory(DirectoryPath);
        var protectedBytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(credential), null, DataProtectionScope.LocalMachine);
        File.WriteAllBytes(CredentialPath, protectedBytes);
    }

    public void Delete()
    {
        if (File.Exists(CredentialPath)) File.Delete(CredentialPath);
    }
}
