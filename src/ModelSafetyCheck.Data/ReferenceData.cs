using System.Text.Json;
using System.Text.Json.Serialization;
using ModelSafetyCheck.Core;

namespace ModelSafetyCheck.Data;

public sealed record RunnerVulnerability(
    string Id,
    string Name,
    string Runner,
    IReadOnlyList<string> Platforms,
    string? Introduced,
    string? Fixed,
    Severity Severity,
    string Summary,
    string Remediation,
    string Confidence,
    IReadOnlyList<string> Sources)
{
    /// <summary>True when <paramref name="installed"/> falls in [Introduced, Fixed) on <paramref name="platform"/>.</summary>
    public bool Affects(string runner, SemVersion installed, string platform) =>
        string.Equals(runner, Runner, StringComparison.OrdinalIgnoreCase) &&
        (Platforms.Count == 0 || Platforms.Contains(platform, StringComparer.OrdinalIgnoreCase)) &&
        (Introduced is null || installed.CompareTo(SemVersion.Parse(Introduced)!) >= 0) &&
        (Fixed is null || installed.CompareTo(SemVersion.Parse(Fixed)!) < 0);
}

public sealed record RunnerVulnerabilityFile(int Version, string Updated, IReadOnlyList<RunnerVulnerability> Vulnerabilities);

public sealed record KnownTemplate(string Family, string Source, string Kind, string? Name, string? Via, string Sha256, string NormalizedSha256, string Text);

public sealed record KnownTemplateFile(int Version, string Generated, IReadOnlyList<KnownTemplate> Templates);

public sealed record TrustedPublisherFile(int Version, string Updated, IReadOnlyList<string> Official, IReadOnlyList<string> Quantizer);

public enum PublisherTier
{
    Unknown,
    Quantizer,
    Official,
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true,
    UseStringEnumConverter = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull, ReadCommentHandling = JsonCommentHandling.Skip)]
[JsonSerializable(typeof(RunnerVulnerabilityFile))]
[JsonSerializable(typeof(KnownTemplateFile))]
[JsonSerializable(typeof(TrustedPublisherFile))]
public sealed partial class DataJsonContext : JsonSerializerContext;

/// <summary>
/// Reference data shipped inside the binary. A copy in ~/.modelcheck/data (or $MODELCHECK_DATA) with a
/// higher "version" overrides the embedded one, so data can be updated without a new release.
/// </summary>
public static class ReferenceData
{
    static readonly Lazy<RunnerVulnerabilityFile> Vulns = new(() =>
        Load("runner-vulns.json", DataJsonContext.Default.RunnerVulnerabilityFile, f => f.Version)
        ?? new RunnerVulnerabilityFile(0, "", []));

    static readonly Lazy<KnownTemplateFile> Templates = new(() =>
        Load("known-templates.json", DataJsonContext.Default.KnownTemplateFile, f => f.Version)
        ?? new KnownTemplateFile(0, "", []));

    static readonly Lazy<TrustedPublisherFile> Publishers = new(() =>
        Load("trusted-publishers.json", DataJsonContext.Default.TrustedPublisherFile, f => f.Version)
        ?? new TrustedPublisherFile(0, "", [], []));

    public static RunnerVulnerabilityFile RunnerVulnerabilities => Vulns.Value;
    public static KnownTemplateFile KnownTemplates => Templates.Value;
    public static TrustedPublisherFile TrustedPublishers => Publishers.Value;

    public static string OverrideDirectory =>
        Environment.GetEnvironmentVariable("MODELCHECK_DATA") is { Length: > 0 } dir
            ? dir
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".modelcheck", "data");

    public static PublisherTier TierOf(string author)
    {
        if (TrustedPublishers.Official.Contains(author, StringComparer.OrdinalIgnoreCase)) return PublisherTier.Official;
        if (TrustedPublishers.Quantizer.Contains(author, StringComparer.OrdinalIgnoreCase)) return PublisherTier.Quantizer;
        return PublisherTier.Unknown;
    }

    static T? Load<T>(string name, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> type, Func<T, int> version) where T : class
    {
        T? embedded = null;
        using (var stream = typeof(ReferenceData).Assembly.GetManifestResourceStream($"data/{name}"))
            if (stream is not null)
                embedded = JsonSerializer.Deserialize(stream, type);

        var overridePath = Path.Combine(OverrideDirectory, name);
        try
        {
            if (File.Exists(overridePath))
            {
                using var stream = File.OpenRead(overridePath);
                var local = JsonSerializer.Deserialize(stream, type);
                if (local is not null && (embedded is null || version(local) > version(embedded)))
                    return local;
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            // A broken override must not stop scanning; the embedded data is still valid.
        }
        return embedded;
    }
}

/// <summary>Lenient version: "v0.17.1", "0.5.11rc1", "0.4.18-build1". Pre-release suffixes sort before the release.</summary>
public sealed record SemVersion(int Major, int Minor, int Patch, string Suffix) : IComparable<SemVersion>
{
    public static SemVersion? Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var m = System.Text.RegularExpressions.Regex.Match(text, @"(\d+)\.(\d+)(?:\.(\d+))?([-+.]?[0-9A-Za-z.\-]*)?");
        if (!m.Success) return null;
        return new SemVersion(int.Parse(m.Groups[1].Value), int.Parse(m.Groups[2].Value),
            m.Groups[3].Success ? int.Parse(m.Groups[3].Value) : 0, m.Groups[4].Value.TrimStart('-', '+', '.'));
    }

    public int CompareTo(SemVersion? other)
    {
        if (other is null) return 1;
        var c = Major.CompareTo(other.Major);
        if (c == 0) c = Minor.CompareTo(other.Minor);
        if (c == 0) c = Patch.CompareTo(other.Patch);
        if (c != 0) return c;
        return (Suffix.Length, other.Suffix.Length) switch
        {
            (0, 0) => 0,
            (0, _) => 1,  // 1.0.0 > 1.0.0-rc1
            (_, 0) => -1,
            _ => string.CompareOrdinal(Suffix, other.Suffix),
        };
    }

    public override string ToString() => Suffix.Length == 0 ? $"{Major}.{Minor}.{Patch}" : $"{Major}.{Minor}.{Patch}-{Suffix}";
}
