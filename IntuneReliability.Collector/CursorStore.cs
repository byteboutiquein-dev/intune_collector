// SPDX-License-Identifier: Apache-2.0

using System.Text.Json;

namespace IntuneReliability.Collector;

public sealed class CursorStore
{
    private static readonly string CursorPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "IntuneReliability", "Collector", "cursors.json");

    public IReadOnlyDictionary<string, FileCursor> Load()
    {
        if (!File.Exists(CursorPath)) return new Dictionary<string, FileCursor>();
        return JsonSerializer.Deserialize<Dictionary<string, FileCursor>>(File.ReadAllText(CursorPath))
            ?? new Dictionary<string, FileCursor>();
    }

    public void Save(IReadOnlyDictionary<string, FileCursor> cursors)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(CursorPath)!);
        var temporary = CursorPath + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(cursors));
        File.Move(temporary, CursorPath, true);
    }
}
