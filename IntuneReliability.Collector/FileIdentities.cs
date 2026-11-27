// SPDX-License-Identifier: Apache-2.0

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace IntuneReliability.Collector;

/// <summary>
/// Identifies a log file by its NTFS volume and file index. Unlike the creation time, that survives a rename
/// (so a rotated log is still recognised) and is never inherited by a new file created under the old name
/// (Windows "file system tunnelling" can copy a creation time onto a replacement file).
/// </summary>
public static class FileIdentities
{
    private const string Prefix = "file:";

    public static string? Read(string path) => OperatingSystem.IsWindows() ? ReadWindows(path) : null;

    /// <summary>
    /// True when a stored cursor identity refers to the file at <paramref name="path"/>. Cursors written by earlier
    /// versions used "creationTicks:length"; those are still matched by creation time, then upgraded on the next save.
    /// </summary>
    public static bool Same(string stored, string? current, string path)
    {
        if (stored.StartsWith(Prefix, StringComparison.Ordinal)) return current is not null && stored == current;
        return File.Exists(path) && stored.Split(':')[0] == File.GetCreationTimeUtc(path).Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    [SupportedOSPlatform("windows")]
    private static string? ReadWindows(string path)
    {
        try
        {
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return GetFileInformationByHandle(handle, out var info)
                ? $"{Prefix}{info.VolumeSerialNumber:x8}-{info.FileIndexHigh:x8}{info.FileIndexLow:x8}"
                : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation information);
}
