using ModelSafetyCheck.Cli;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Tests;

public sealed class ReportArchiveTests : IDisposable
{
    readonly string _dir = Path.Combine(Path.GetTempPath(), "modelcheck-archive-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, recursive: true);
    }

    [Fact]
    public void Save_keeps_every_finding_and_the_exit_code()
    {
        Directory.CreateDirectory(_dir);
        var model = Path.Combine(_dir, "bad.gguf");
        File.WriteAllBytes(model, GgufWriter.Minimal("{{ lipsum.__globals__ }}").Build());
        var reports = Path.Combine(_dir, "reports");

        // --min-severity hides findings on screen; the saved copy must still have them.
        var code = Program.Main(["scan", model, "--save", reports, "--no-policy", "--min-severity", "critical", "--format", "jsonl"]);

        var file = Assert.Single(Directory.GetFiles(reports));
        Assert.Matches(@"\d{8}-\d{6}-scan\.json$", file);
        var run = ReportArchive.Load(file)!;
        Assert.Equal("scan", run.Command);
        Assert.Equal(code, run.ExitCode);
        Assert.Contains(model, run.Arguments);
        var report = Assert.Single(run.Reports);
        Assert.Equal(model, report.Target);
        Assert.NotEmpty(report.Findings);
        Assert.Contains(report.Findings, f => f.Severity < Severity.Critical);
        Assert.True(run.Finished >= run.Started);
    }

    [Fact]
    public void Runs_in_the_same_second_do_not_overwrite_each_other()
    {
        var run = new SavedRun(1, "repo", ["repo", "org/model"], DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, 0,
            [new ScanReport { Target = "org/model", Kind = "hf" }]);
        var first = ReportArchive.Save(run, _dir);
        var second = ReportArchive.Save(run, _dir);
        Assert.NotEqual(first, second);
        Assert.EndsWith("-repo-2.json", second);
        Assert.Equal(2, Directory.GetFiles(_dir).Length);
    }
}
