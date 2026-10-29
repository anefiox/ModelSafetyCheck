using System.CommandLine;
using ModelSafetyCheck.Rules.Policy;

namespace ModelSafetyCheck.Cli;

public static class PolicyCommand
{
    public const string Template = """
        # modelcheck policy. Docs: docs/rules.md#policy-files
        version: 1

        # Counting findings at or above this severity fail the run (exit 2): info, low, medium, high, critical or never.
        fail-on: high

        # Provenance findings (H006-H008, H011, P001-P003) for these become Info. Globs: * within a segment, ** across '/'.
        allow:
          publishers: []
          #  - meta-llama
          #  - library          # official Ollama models
          models: []
          #  - hf:Qwen/Qwen2.5-*

        # Per-rule severity, or off to drop the rule entirely.
        severity:
        #  T009: low
        #  P002: off

        # Accepted findings. Each needs a reason and an expiry date; expired entries stop applying (rule PL001).
        suppress: []
        #  - rule: H007
        #    target: "hf:my-org/**"
        #    location: general.base_model   # optional
        #    reason: Fine-tune of our own model; lineage reviewed in TICKET-123
        #    expires: 2027-03-31

        # Known findings recorded with 'modelcheck ... --write-baseline <file>'; only new findings count.
        # baseline: .modelcheck-baseline.json
        """;

    public static Command Create()
    {
        var file = new Argument<string?>("file") { Description = "Policy file; default: the one found from the current directory upwards.", Arity = ArgumentArity.ZeroOrOne };
        var check = new Command("check", "Validate a policy file and show what it does: suppressions (with expiry), overrides, allow-lists and baseline.") { file };
        check.SetAction(result => Check(result.GetValue(file), Console.Out));

        var force = new Option<bool>("--force") { Description = "Overwrite an existing file." };
        var output = new Option<string>("--output", "-o") { Description = "Where to write it.", DefaultValueFactory = _ => ".modelcheck.yml" };
        var init = new Command("init", "Write a commented starter .modelcheck.yml.") { output, force };
        init.SetAction(result => Init(result.GetValue(output)!, result.GetValue(force), Console.Out));

        return new Command("policy", "Team policy: allow-lists, suppressions with expiry, severity overrides, fail-on and baselines (.modelcheck.yml).") { check, init };
    }

    internal static int Init(string path, bool force, TextWriter output)
    {
        if (File.Exists(path) && !force)
        {
            Console.Error.WriteLine($"{path} already exists (use --force to overwrite).");
            return Program.ExitError;
        }
        File.WriteAllText(path, Template + "\n");
        output.WriteLine($"Wrote {path}. Check it with: modelcheck policy check {path}");
        return Program.ExitClean;
    }

    /// <summary>Exit 0 when valid, 1 when valid but with expired suppressions or a missing baseline, 3 when invalid.</summary>
    internal static int Check(string? path, TextWriter output, DateOnly? today = null)
    {
        path ??= ModelPolicy.Discover(Environment.CurrentDirectory);
        if (path is null)
        {
            output.WriteLine($"No policy file found in {Environment.CurrentDirectory} or its parents ({string.Join(", ", ModelPolicy.FileNames)}). Create one with: modelcheck policy init");
            return Program.ExitClean;
        }

        ModelPolicy policy;
        try
        {
            if (!File.Exists(path)) throw new PolicyException("file not found.");
            policy = ModelPolicy.Load(path);
        }
        catch (Exception ex) when (ex is PolicyException or IOException or UnauthorizedAccessException)
        {
            output.WriteLine($"INVALID {path}: {ex.Message}");
            return Program.ExitError;
        }

        var now = today ?? DateOnly.FromDateTime(DateTime.UtcNow);
        var warnings = 0;
        output.WriteLine($"Policy {Path.GetFullPath(path)} is valid.");
        output.WriteLine($"  fail-on: {policy.FailOn?.ToString().ToLowerInvariant() ?? "never"}");
        output.WriteLine($"  allow.publishers: {List(policy.AllowPublishers)}");
        output.WriteLine($"  allow.models: {List(policy.AllowModels)}");
        output.WriteLine($"  severity: {(policy.SeverityOverrides.Count == 0 ? "(none)" : string.Join(", ", policy.SeverityOverrides.Select(o => $"{o.Key}={o.Value?.ToString().ToLowerInvariant() ?? "off"}")))}");
        output.WriteLine($"  suppress: {(policy.Suppressions.Count == 0 ? "(none)" : "")}");
        foreach (var s in policy.Suppressions)
        {
            var days = s.Expires.DayNumber - now.DayNumber;
            var state = days < 0 ? $"EXPIRED {-days} day(s) ago" : days <= 30 ? $"expires in {days} day(s)" : "active";
            if (days < 0) warnings++;
            output.WriteLine($"    [{s.Index}] {s.Rule} on {s.Target}{(s.Location is null ? "" : $" at {s.Location}")} until {s.Expires:yyyy-MM-dd} ({state}): {s.Reason}");
        }
        if (policy.BaselinePath is { } baseline)
        {
            if (!File.Exists(baseline))
            {
                warnings++;
                output.WriteLine($"  baseline: {baseline} (MISSING; create it with --write-baseline {baseline})");
            }
            else
            {
                try
                {
                    output.WriteLine($"  baseline: {baseline} ({PolicyEngine.LoadBaseline(baseline).Entries.Count} known finding(s))");
                }
                catch (PolicyException ex)
                {
                    output.WriteLine($"INVALID baseline: {ex.Message}");
                    return Program.ExitError;
                }
            }
        }
        else
            output.WriteLine("  baseline: (none)");
        return warnings > 0 ? Program.ExitWarnings : Program.ExitClean;
    }

    static string List(IReadOnlyList<string> items) => items.Count == 0 ? "(none)" : string.Join(", ", items);
}
