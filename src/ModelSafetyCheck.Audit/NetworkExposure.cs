using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using ModelSafetyCheck.Core;

namespace ModelSafetyCheck.Audit;

public sealed record AiPort(int Port, string Runner, bool Dedicated, string ProbePath);

/// <summary>Layer 4: who can talk to the model. Configuration, live sockets, Docker port mappings and an optional probe.</summary>
public static partial class NetworkExposure
{
    public static readonly AiPort[] KnownPorts =
    [
        new(11434, "Ollama", true, "/api/version"),
        new(1234, "LM Studio", true, "/v1/models"),
        new(30000, "SGLang", true, "/v1/models"),
        new(8080, "llama.cpp server (default port)", false, "/v1/models"),
        new(8000, "vLLM (default port)", false, "/v1/models"),
        new(5001, "KoboldCpp (default port)", false, "/v1/models"),
    ];

    const string Remedy = "Keep the server on 127.0.0.1. To reach it from other devices, use an encrypted tunnel (e.g. Tailscale) or a reverse proxy that requires authentication instead of binding to every interface.";

    [GeneratedRegex(@"OLLAMA_(HOST|ORIGINS)=""?([^""\s]+)")]
    private static partial Regex SystemdEnvRegex();

    [GeneratedRegex(@"(?<host>\d{1,3}(?:\.\d{1,3}){3}|\[?::\]?|::):(?<hostPort>\d+)->(?<containerPort>\d+)/tcp")]
    private static partial Regex DockerPortRegex();

    [GeneratedRegex("ollama|vllm|sglang|llama|lmstudio|lm-studio|text-generation|tgi|localai|koboldcpp|open-webui", RegexOptions.IgnoreCase)]
    private static partial Regex AiImageRegex();

    /// <summary>OLLAMA_HOST / OLLAMA_ORIGINS from the process, user and machine environment, systemd units and launchd.</summary>
    public static IEnumerable<Finding> CheckOllamaConfig()
    {
        foreach (var (name, value, source) in OllamaSettings())
        {
            if (name == "OLLAMA_HOST" && IsExposedHost(value, out var how))
                yield return new Finding("A002", Severity.High, "Ollama is configured to listen beyond this machine",
                    $"OLLAMA_HOST={value} ({how}) in {source}. Anyone who can route to this machine can use the model and its tools, and Ollama skips its DNS-rebinding host check when not bound to loopback, so web pages you visit can reach it too.\nFix: {Remedy}",
                    source);
            else if (name == "OLLAMA_ORIGINS" && value.Split(',').Any(o => o.Trim() == "*"))
                yield return new Finding("A003", Severity.High, "Ollama accepts requests from any web origin",
                    $"OLLAMA_ORIGINS={value} in {source}. Any website you open can call the Ollama API from your browser, for example to read or rewrite a model's chat template.\nFix: remove '*' and list only the origins you use.",
                    source);
        }
    }

    static IEnumerable<(string Name, string Value, string Source)> OllamaSettings()
    {
        foreach (var name in new[] { "OLLAMA_HOST", "OLLAMA_ORIGINS" })
        {
            if (Environment.GetEnvironmentVariable(name) is { Length: > 0 } process)
                yield return (name, process, "this shell's environment");
            if (OperatingSystem.IsWindows())
            {
                if (Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.User) is { Length: > 0 } user)
                    yield return (name, user, "Windows user environment variables");
                if (Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Machine) is { Length: > 0 } machine)
                    yield return (name, machine, "Windows system environment variables");
            }
            if (OperatingSystem.IsMacOS() && ProcessRunner.Run("launchctl", ["getenv", name], TimeSpan.FromSeconds(3)) is { ExitCode: 0, Output: { Length: > 0 } launchd })
                yield return (name, launchd.Trim(), "launchctl environment");
        }

        if (OperatingSystem.IsLinux())
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var units = new[] { "/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system", Path.Combine(home, ".config/systemd/user") }
                .SelectMany(dir => new[] { Path.Combine(dir, "ollama.service") }
                    .Concat(Directory.Exists(Path.Combine(dir, "ollama.service.d")) ? Directory.GetFiles(Path.Combine(dir, "ollama.service.d"), "*.conf") : []))
                .Append("/etc/environment")
                .Where(File.Exists);
            foreach (var unit in units)
            {
                string text;
                try { text = File.ReadAllText(unit); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }
                foreach (Match m in SystemdEnvRegex().Matches(text))
                    yield return ($"OLLAMA_{m.Groups[1].Value}", m.Groups[2].Value, unit);
            }
        }
    }

    public static bool IsExposedHost(string value, out string how)
    {
        var host = value.Trim().Trim('"', '\'');
        host = Regex.Replace(host, "^[a-z]+://", "", RegexOptions.IgnoreCase);
        if (host.StartsWith('['))
            host = host[1..Math.Max(1, host.IndexOf(']'))];
        else if (host.Count(c => c == ':') == 1)
            host = host[..host.IndexOf(':')];

        how = "";
        if (host.Length == 0 || host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
            return false;
        if (host is "0.0.0.0" or "::" or "*")
        {
            how = "every network interface";
            return true;
        }
        if (IPAddress.TryParse(host, out var ip))
        {
            if (IPAddress.IsLoopback(ip)) return false;
            how = "a network interface";
            return true;
        }
        how = "a host name that may resolve to a network address";
        return true;
    }

    public sealed record Listener(IPEndPoint EndPoint, AiPort Port);

    /// <summary>Known AI ports that are listening on something other than loopback.</summary>
    public static List<Listener> ExposedListeners()
    {
        var listeners = new List<IPEndPoint>();
        try
        {
            listeners.AddRange(IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners());
        }
        catch (Exception ex) when (ex is PlatformNotSupportedException or NetworkInformationException)
        {
            listeners.AddRange(LsofListeners());
        }

        return listeners
            .Where(e => !IPAddress.IsLoopback(e.Address))
            .Select(e => (EndPoint: e, Port: KnownPorts.FirstOrDefault(p => p.Port == e.Port)))
            .Where(x => x.Port is not null)
            .Select(x => new Listener(x.EndPoint, x.Port!))
            .DistinctBy(l => l.EndPoint.ToString())
            .ToList();
    }

    static IEnumerable<IPEndPoint> LsofListeners()
    {
        var result = ProcessRunner.Run("lsof", ["-nP", "-iTCP", "-sTCP:LISTEN"], TimeSpan.FromSeconds(5));
        if (result is null)
            yield break;
        foreach (Match m in Regex.Matches(result.Output, @"TCP (\*|\[?[0-9a-fA-F:.]+\]?):(\d+) \(LISTEN\)"))
        {
            var host = m.Groups[1].Value.Trim('[', ']');
            var address = host == "*" ? IPAddress.Any : IPAddress.TryParse(host, out var ip) ? ip : null;
            if (address is not null)
                yield return new IPEndPoint(address, int.Parse(m.Groups[2].Value));
        }
    }

    public static IEnumerable<Finding> CheckListeners(List<Listener> exposed)
    {
        foreach (var l in exposed)
        {
            var scope = l.EndPoint.Address.Equals(IPAddress.Any) || l.EndPoint.Address.Equals(IPAddress.IPv6Any) ? "every network interface" : l.EndPoint.Address.ToString();
            yield return new Finding("A004", l.Port.Dedicated ? Severity.High : Severity.Medium,
                $"{l.Port.Runner} port {l.Port.Port} is listening on {scope}",
                $"Port {l.Port.Port} is open to the network{(l.Port.Dedicated ? "" : " (if this is an AI server)")}. On untrusted networks anyone nearby can use the model, its tools and its API.\nFix: {Remedy} Run with --probe to test whether it answers without authentication.",
                l.EndPoint.ToString());
        }
    }

    /// <summary>Docker publishes ports with its own firewall rules, which bypass ufw/firewalld on Linux.</summary>
    public static IEnumerable<Finding> CheckDocker()
    {
        var result = ProcessRunner.Run("docker", ["ps", "--format", "{{json .}}"], TimeSpan.FromSeconds(8));
        if (result is null || result.ExitCode != 0)
            yield break;

        foreach (var line in result.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            string image, name, ports;
            try
            {
                using var doc = JsonDocument.Parse(line);
                image = doc.RootElement.GetProperty("Image").GetString() ?? "";
                name = doc.RootElement.GetProperty("Names").GetString() ?? "";
                ports = doc.RootElement.GetProperty("Ports").GetString() ?? "";
            }
            catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
            {
                continue;
            }

            foreach (Match m in DockerPortRegex().Matches(ports))
            {
                var host = m.Groups["host"].Value.Trim('[', ']');
                var containerPort = int.Parse(m.Groups["containerPort"].Value);
                var isAi = AiImageRegex().IsMatch(image) || KnownPorts.Any(p => p.Port == containerPort && p.Dedicated);
                if (host is not ("0.0.0.0" or "::") || !isAi)
                    continue;
                var ufw = OperatingSystem.IsLinux() ? " Docker writes its own iptables rules, so ufw/firewalld rules do not protect this port." : "";
                yield return new Finding("A005", Severity.High, $"Docker container '{name}' publishes an AI port on all interfaces",
                    $"{image} maps {m.Value}.{ufw}\nFix: publish it on loopback only, e.g. -p 127.0.0.1:{m.Groups["hostPort"].Value}:{containerPort}.",
                    $"docker:{name}");
                break;
            }
        }
    }

    /// <summary>Opt-in: asks each exposed server, via this machine's own LAN addresses, whether it answers without credentials.</summary>
    public static IEnumerable<Finding> Probe(List<Listener> exposed, HttpClient http)
    {
        foreach (var l in exposed)
        {
            var addresses = l.EndPoint.Address.Equals(IPAddress.Any) || l.EndPoint.Address.Equals(IPAddress.IPv6Any)
                ? LanAddresses()
                : [l.EndPoint.Address];
            foreach (var address in addresses)
            {
                var host = address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{address}]" : address.ToString();
                var url = $"http://{host}:{l.Port.Port}{l.Port.ProbePath}";
                HttpStatusCode? status = null;
                try
                {
                    using var response = http.Send(new HttpRequestMessage(HttpMethod.Get, url));
                    status = response.StatusCode;
                }
                catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
                {
                }

                if (status is HttpStatusCode.OK)
                    yield return new Finding("A006", Severity.Critical, $"{l.Port.Runner} answers on the network without authentication",
                        $"GET {url} returned 200 with no credentials. Any device that can reach {address} can use this server.\nFix: {Remedy}", url);
                else if (status is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                    yield return new Finding("A006", Severity.Info, $"{l.Port.Runner} requires authentication on the network",
                        $"GET {url} returned {(int)status}.", url);
                break;
            }
        }
    }

    static IEnumerable<IPAddress> LanAddresses() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses)
            .Select(a => a.Address)
            .Where(a => a.AddressFamily == AddressFamily.InterNetwork && !a.ToString().StartsWith("169.254.", StringComparison.Ordinal))
            .Take(4);
}
