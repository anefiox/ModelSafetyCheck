using System.Diagnostics;
using System.Text.RegularExpressions;
using ModelSafetyCheck.Core;

namespace ModelSafetyCheck.Audit;

public sealed record PortOwner(int Pid, string Name);

/// <summary>
/// Which process is listening on a port (A-10). Uses the platform's own tool (netstat / ss / lsof);
/// without admin rights some owners may be unknown, which only means less detail in the report.
/// </summary>
public static partial class PortOwners
{
    [GeneratedRegex(@"^\s*TCP\s+(?<addr>\S+):(?<port>\d+)\s+\S+\s+LISTENING\s+(?<pid>\d+)", RegexOptions.Multiline)]
    private static partial Regex NetstatRegex();

    [GeneratedRegex(@":(?<port>\d+)\s+\S+\s+users:\(\(""(?<name>[^""]+)"",pid=(?<pid>\d+)")]
    private static partial Regex SsRegex();

    [GeneratedRegex(@"^(?<name>\S+)\s+(?<pid>\d+)\s.*TCP \S+:(?<port>\d+) \(LISTEN\)", RegexOptions.Multiline)]
    private static partial Regex LsofRegex();

    [GeneratedRegex("ollama|lm ?studio|lms|llama|llamafile|vllm|sglang|koboldcpp|text-generation|tgi|localai|jan|gpt4all|python|docker|com.docker|wslrelay", RegexOptions.IgnoreCase)]
    private static partial Regex AiProcessRegex();

    public static Dictionary<int, PortOwner> Find()
    {
        var owners = new Dictionary<int, PortOwner>();
        if (OperatingSystem.IsWindows())
        {
            var result = ProcessRunner.Run("netstat", ["-ano", "-p", "TCP"], TimeSpan.FromSeconds(10));
            var v6 = ProcessRunner.Run("netstat", ["-ano", "-p", "TCPv6"], TimeSpan.FromSeconds(10));
            foreach (Match m in NetstatRegex().Matches((result?.Output ?? "") + (v6?.Output ?? "")))
                owners.TryAdd(int.Parse(m.Groups["port"].Value), new PortOwner(int.Parse(m.Groups["pid"].Value), NameOf(int.Parse(m.Groups["pid"].Value))));
        }
        else if (OperatingSystem.IsLinux())
        {
            var result = ProcessRunner.Run("ss", ["-ltnpH"], TimeSpan.FromSeconds(10));
            foreach (Match m in SsRegex().Matches(result?.Output ?? ""))
                owners.TryAdd(int.Parse(m.Groups["port"].Value), new PortOwner(int.Parse(m.Groups["pid"].Value), m.Groups["name"].Value));
        }
        else
        {
            var result = ProcessRunner.Run("lsof", ["-nP", "-iTCP", "-sTCP:LISTEN"], TimeSpan.FromSeconds(10));
            foreach (Match m in LsofRegex().Matches(result?.Output ?? ""))
                owners.TryAdd(int.Parse(m.Groups["port"].Value), new PortOwner(int.Parse(m.Groups["pid"].Value), m.Groups["name"].Value));
        }
        return owners;
    }

    /// <summary>True when the owner is unknown or looks like a model server (or a container/VM that may host one).</summary>
    public static bool MayBeAiServer(PortOwner? owner) => owner is null || AiProcessRegex().IsMatch(owner.Name);

    static string NameOf(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return process.ProcessName;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return $"pid {pid}";
        }
    }
}
