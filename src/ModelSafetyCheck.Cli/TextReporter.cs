using ModelSafetyCheck.Core;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Cli;

sealed class TextReporter(TextWriter output, bool color)
{
    public void Write(ScanReport report, bool dumpTemplates)
    {
        output.WriteLine();
        WithColor(ConsoleColor.White, () => output.Write($"==> {report.Target}"));
        if (report.Summary is { } s)
            output.Write($"  (GGUF v{s.Version}, {s.Architecture ?? "unknown arch"}, {FormatBytes(s.FileSize)}, {s.TensorCount} tensors, {report.Templates.Count} template(s))");
        output.WriteLine();
        if (report.Summary is { Name: { } name })
            output.WriteLine($"    name: {name}");
        if (report.Summary is { BaseModels.Count: > 0 } summary)
            output.WriteLine($"    base: {string.Join("; ", summary.BaseModels)}");

        if (report.Error is not null)
            WithColor(ConsoleColor.Red, () => output.WriteLine($"    ERROR: {report.Error}"));

        foreach (var finding in report.Findings)
        {
            output.Write("    ");
            WithColor(ColorOf(finding.Severity), () => output.Write($"[{finding.Severity.ToString().ToUpperInvariant()}]".PadRight(11)));
            output.Write($"{finding.RuleId}  {finding.Title}");
            if (finding.Location is not null)
                WithColor(ConsoleColor.DarkGray, () => output.Write($"  ({finding.Location})"));
            output.WriteLine();
            foreach (var line in finding.Detail.Split('\n'))
                output.WriteLine($"               {line}");
        }

        if (!dumpTemplates)
            return;
        foreach (var template in report.Templates)
        {
            WithColor(ConsoleColor.Cyan, () => output.WriteLine($"    ---- template {template.Location} ({template.Dialect}) ----"));
            output.WriteLine(template.Text);
            WithColor(ConsoleColor.Cyan, () => output.WriteLine("    ---- end template ----"));
        }
    }

    public void WriteSummary(IReadOnlyList<ScanReport> reports)
    {
        WriteSummary(reports.Count, reports.Count(r => r.Error is not null),
            Enum.GetValues<Severity>().Select(sev => (long)reports.Sum(r => r.Findings.Count(f => f.Severity == sev))).ToArray());
    }

    public void WriteSummary(long reportCount, long errorCount, IReadOnlyList<long> severityCounts)
    {
        var counts = Enum.GetValues<Severity>().Reverse()
            .Select(sev => $"{severityCounts[(int)sev]} {sev.ToString().ToLowerInvariant()}");
        output.WriteLine();
        output.WriteLine($"Scanned {reportCount} target(s): {string.Join(", ", counts)}; {errorCount} error(s).");
        output.WriteLine("Note: a clean result means no known file, template or setup issue was found. It cannot prove the weights are free of backdoors.");
    }

    void WithColor(ConsoleColor consoleColor, Action write)
    {
        if (!color)
        {
            write();
            return;
        }
        output.Flush();
        Console.ForegroundColor = consoleColor;
        write();
        output.Flush();
        Console.ResetColor();
    }

    static ConsoleColor ColorOf(Severity severity) => severity switch
    {
        Severity.Critical => ConsoleColor.Magenta,
        Severity.High => ConsoleColor.Red,
        Severity.Medium => ConsoleColor.Yellow,
        Severity.Low => ConsoleColor.DarkYellow,
        _ => ConsoleColor.Gray,
    };

    static string FormatBytes(long bytes) => bytes switch
    {
        >= 1L << 30 => $"{bytes / (double)(1L << 30):0.0} GB",
        >= 1L << 20 => $"{bytes / (double)(1L << 20):0.0} MB",
        _ => $"{bytes / 1024.0:0.0} KB",
    };
}
