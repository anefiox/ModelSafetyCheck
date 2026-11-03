using System.Net;
using ModelSafetyCheck.Cli;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Hub;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Tests;

public sealed class ExportTests : IDisposable
{
    readonly string _dir = Path.Combine(Path.GetTempPath(), "modelcheck-export-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, recursive: true);
    }

    static SavedRun Run(string command, DateTimeOffset started, params ScanReport[] reports) =>
        new(1, command, [command], started, started, 0, [.. reports], "0.3.0");

    static ScanReport Report(string target, params Finding[] findings) => new() { Target = target, Kind = "hf", Findings = [.. findings] };

    [Theory]
    [InlineData("hf:org/name", "org/name", null)]
    [InlineData("hf:org/name/sub/model.gguf", "org/name", "sub/model.gguf")]
    [InlineData("org/name/model.gguf", "org/name", "model.gguf")]
    [InlineData("https://example.org/model.gguf", null, null)]
    [InlineData("ollama:llama3.2", null, null)]
    public void Targets_split_into_repo_and_file(string target, string? repo, string? file) =>
        Assert.Equal((repo, file), ExportCommand.SplitTarget(target));

    [Fact]
    public void Export_keeps_the_latest_scan_of_each_target_and_leaves_out_local_runs()
    {
        var reports = Path.Combine(_dir, "reports");
        var t0 = new DateTimeOffset(2026, 10, 30, 10, 0, 0, TimeSpan.Zero);
        ReportArchive.Save(Run("repo", t0, Report("hf:a/m", new Finding("T004", Severity.High, "Old", "old rule"))), reports);
        ReportArchive.Save(Run("repo", t0.AddHours(1), Report("hf:a/m", new Finding("T004", Severity.Low, "Suspicious", "=HYPERLINK(\"x\"), \"quoted\""))), reports);
        ReportArchive.Save(Run("batch", t0, Report("hf:b/n/file.gguf", new Finding("S006", Severity.Medium, "Unknown tensor type", "type 143",
            @"C:\Users\someone\modelcheck-batch\downloads\x\file.gguf"))), reports);
        ReportArchive.Save(Run("local", t0, Report(@"C:\Users\someone\models\secret.gguf")), reports);

        var output = Path.Combine(_dir, "out");
        var log = new StringWriter();
        Assert.Equal(0, ExportCommand.Run(reports, output, includeLocal: false, log));

        var findings = File.ReadAllLines(Path.Combine(output, "findings.csv"));
        Assert.Equal(3, findings.Length);
        Assert.DoesNotContain(findings, l => l.Contains("old rule"));
        // A leading = is neutralised so a spreadsheet does not run it as a formula; quotes are doubled.
        Assert.Contains(findings, l => l.Contains("\"'=HYPERLINK(\"\"x\"\"), \"\"quoted\"\"\""));
        Assert.Contains(findings, l => l.Contains(",file.gguf,") && !l.Contains(@"C:\Users"));

        var all = string.Concat(Directory.GetFiles(output).Select(File.ReadAllText));
        Assert.DoesNotContain("someone", all);
        var targets = File.ReadAllLines(Path.Combine(output, "targets.jsonl"));
        Assert.Equal(2, targets.Length);
        Assert.Contains(targets, l => l.Contains("\"repo\":\"b/n\"") && l.Contains("\"file\":\"file.gguf\"") && l.Contains("\"max_severity\":\"medium\""));
        var readme = File.ReadAllText(Path.Combine(output, "README.md"));
        Assert.Contains("Scanned 2 Hugging Face repo(s) and 1 model file(s)", readme);
        Assert.Contains("| S006 | medium | Unknown tensor type | 1 | 1 |", readme);
        Assert.Contains("Left out 1 run(s)", log.ToString());
    }

    [Fact]
    public void A_batch_directory_exports_without_saved_runs()
    {
        var batch = Path.Combine(_dir, "batch");
        Directory.CreateDirectory(Path.Combine(batch, "results"));
        var result = new BatchResult("hf:a/m/model.gguf", new string('a', 40), new string('f', 64),
            new DateTimeOffset(2026, 11, 3, 9, 0, 0, TimeSpan.Zero), true,
            [new DownloadReceipt("model.gguf", "https://huggingface.co/a/m/resolve/x/model.gguf", 5, new string('b', 64))],
            [Report("hf:a/m/model.gguf/model.gguf", new Finding("T004", Severity.High, "Trigger", "if date"))]);
        File.WriteAllText(Path.Combine(batch, "results", "key.json"),
            System.Text.Json.JsonSerializer.Serialize(result, BatchJsonContext.Default.BatchResult));

        var output = Path.Combine(_dir, "out");
        Assert.Equal(0, ExportCommand.Run(null, output, includeLocal: false, new StringWriter(), [batch]));
        var target = Assert.Single(File.ReadAllLines(Path.Combine(output, "targets.jsonl")));
        Assert.Contains("\"max_severity\":\"high\"", target);
        Assert.Contains("\"scanner_version\":\"build ffffffffffff\"", target);
        Assert.Contains($"\"sha256\":\"{new string('b', 64)}\"", target);
    }

    sealed class FlakyHandler : HttpMessageHandler
    {
        public int Calls;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            ++Calls == 1
                ? throw new HttpRequestException("The SSL connection could not be established")
                : Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("ok") });
    }

    [Fact]
    public async Task Async_requests_retry_a_connection_that_was_never_established()
    {
        var handler = new FlakyHandler();
        using var hub = new HuggingFaceClient(handler);
        Assert.Equal("ok", await hub.Http.GetStringAsync("https://example.org/file"));
        Assert.Equal(2, handler.Calls);
    }
}
