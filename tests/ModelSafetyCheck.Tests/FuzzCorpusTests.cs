using System.IO.Compression;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Tests;

/// <summary>
/// Regression corpus from a coverage-guided libFuzzer run (tools/Fuzz): 1,095 minimized inputs that together
/// reach every code path the fuzzer found. Every one must scan without an exception.
/// </summary>
public class FuzzCorpusTests
{
    [Fact]
    public void Libfuzzer_corpus_scans_without_exceptions()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Fuzz", "libfuzzer-corpus.zip");
        using var zip = ZipFile.OpenRead(path);
        Assert.True(zip.Entries.Count > 1000);
        foreach (var entry in zip.Entries)
        {
            using var stream = entry.Open();
            using var buffer = new MemoryStream();
            stream.CopyTo(buffer);
            buffer.Position = 0;
            var report = ModelScanner.ScanStream(buffer, entry.Name);
            Assert.Null(report.Error);
        }
    }
}
