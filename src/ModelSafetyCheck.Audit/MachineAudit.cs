using ModelSafetyCheck.Core;
using ModelSafetyCheck.Data;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Audit;

public sealed record AuditOptions(string? AgentDirectory = null, bool Probe = false);

/// <summary>
/// The `audit` command: checks layers 3-5 of the local setup (runner, network, agent) and rolls up
/// layers 1-2 from the model scans into one risk rating.
/// </summary>
public static class MachineAudit
{
    public static ScanReport Run(AuditOptions options, IReadOnlyList<ScanReport> modelReports)
    {
        var report = new ScanReport { Target = $"this machine ({Environment.MachineName}, {RunnerDetector.Platform})", Kind = "audit" };
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };

        var runners = RunnerDetector.Detect(http);
        report.Findings.AddRange(CheckRunners(runners));

        report.Findings.AddRange(NetworkExposure.CheckOllamaConfig());
        var exposed = NetworkExposure.ExposedListeners();
        report.Findings.AddRange(NetworkExposure.CheckListeners(exposed));
        report.Findings.AddRange(NetworkExposure.CheckDocker());
        if (options.Probe)
            report.Findings.AddRange(NetworkExposure.Probe(exposed, http));

        if (options.AgentDirectory is not null)
        {
            report.Findings.AddRange(SecretScanner.Scan(Path.GetFullPath(options.AgentDirectory)));
            report.Findings.Add(new Finding("G003", Severity.Info, "Separate the agent's powers",
                "Run the process that executes commands without network access, and the process with network access without a shell, and log what passes between them. " +
                "A backdoored model then cannot both read files and send them out.", options.AgentDirectory));
        }

        report.Findings.Add(RiskSummary(report.Findings, modelReports, options.AgentDirectory is not null));
        return report;
    }

    static IEnumerable<Finding> CheckRunners(List<DetectedRunner> runners)
    {
        var data = ReferenceData.RunnerVulnerabilities;
        foreach (var runner in runners)
        {
            var version = SemVersion.Parse(runner.Version);
            yield return new Finding("A007", Severity.Info, $"Found {runner.Runner} {runner.Version ?? "(version unknown)"}", $"Detected via {runner.Source}.", runner.Runner);
            if (version is null)
                continue;

            foreach (var v in data.Vulnerabilities.Where(v => v.Affects(runner.Runner, version, RunnerDetector.Platform)))
            {
                var fixedText = v.Fixed is null ? "No fixed release is known." : $"Fixed in {v.Fixed}{(v.Confidence == "confirmed" ? "" : " (reported by third parties; confirm in the release notes)")}.";
                yield return new Finding("A001", v.Severity, $"{runner.Runner} {version} is affected by {v.Id} ({v.Name})",
                    $"{v.Summary} {fixedText}\nFix: {v.Remediation}\nSources: {string.Join(" ", v.Sources)}", runner.Runner);
            }
        }
    }

    /// <summary>One rating per layer, plus an overall rating that escalates when layers combine (e.g. exposed AND vulnerable).</summary>
    static Finding RiskSummary(List<Finding> findings, IReadOnlyList<ScanReport> modelReports, bool agentChecked)
    {
        Severity Max(IEnumerable<Finding> f) => f.Select(x => x.Severity).DefaultIfEmpty(Severity.Info).Max();

        var models = modelReports.SelectMany(r => r.Findings).ToList();
        var file = Max(models.Where(f => f.RuleId[0] is 'S' or 'M' or 'K' or 'O'));
        var template = Max(models.Where(f => f.RuleId[0] == 'T'));
        var runner = Max(findings.Where(f => f.RuleId == "A001"));
        var network = Max(findings.Where(f => f.RuleId is "A002" or "A003" or "A004" or "A005" or "A006"));
        var agent = Max(findings.Where(f => f.RuleId == "G001"));

        var overall = new[] { file, template, runner, network, agent }.Max();
        var reasons = new List<string>();
        if (network >= Severity.High && runner >= Severity.High)
        {
            overall = Severity.Critical;
            reasons.Add("a vulnerable runner is reachable from the network");
        }
        if (network >= Severity.High && agent >= Severity.High)
        {
            overall = Severity.Critical;
            reasons.Add("an exposed server can drive an agent that can read secrets");
        }

        string Line(string layer, Severity severity, string note = "") =>
            $"\n  {layer,-24} {(severity <= Severity.Info ? "ok" : severity.ToString().ToLowerInvariant()),-9}{note}";
        var detail =
            Line("L1 model files", file, $" ({modelReports.Count} model(s) scanned)") +
            Line("L2 chat templates", template) +
            Line("L3 runners", runner) +
            Line("L4 network exposure", network) +
            Line("L5 agent / tools", agent, agentChecked ? "" : " (not checked; pass --agent-dir)") +
            (reasons.Count > 0 ? $"\nEscalated because {string.Join(" and ", reasons)}." : "") +
            "\nWeights can contain trained-in backdoors that no scan detects: give agents official weights only and keep secrets out of their reach.";

        var title = overall <= Severity.Info ? "Overall risk: no known issues" : $"Overall risk: {overall.ToString().ToLowerInvariant()}";
        return new Finding("G002", overall, title, detail.TrimStart('\n'), null);
    }
}
