using System.Text;
using System.Text.RegularExpressions;
using ModelSafetyCheck.Core;

namespace ModelSafetyCheck.Rules;

public sealed record InvisibleCharReport(int Tags, int Bidi, int ZeroWidth, int VariationSelectors, int PrivateUse, string DecodedTagText)
{
    public bool Any => Tags + Bidi + ZeroWidth + VariationSelectors + PrivateUse > 0;

    public Severity Severity =>
        Tags > 0 ? Severity.Critical :
        Bidi > 0 || VariationSelectors > 3 ? Severity.High :
        ZeroWidth > 0 || VariationSelectors > 0 ? Severity.Medium :
        Severity.Low;

    public string Describe()
    {
        var parts = new List<string>();
        if (Tags > 0) parts.Add($"{Tags} Unicode tag characters (invisible ASCII) decoding to \"{TextHeuristics.Truncate(DecodedTagText, 200)}\"");
        if (Bidi > 0) parts.Add($"{Bidi} bidirectional override/isolate characters");
        if (ZeroWidth > 0) parts.Add($"{ZeroWidth} zero-width characters");
        if (VariationSelectors > 0) parts.Add($"{VariationSelectors} variation selectors (can smuggle hidden bytes)");
        if (PrivateUse > 0) parts.Add($"{PrivateUse} private-use characters");
        return string.Join("; ", parts);
    }
}

public sealed record PhraseMatch(string Description, Severity Severity, string Match);

/// <summary>Content heuristics shared by template, system prompt and metadata rules.</summary>
public static partial class TextHeuristics
{
    public static InvisibleCharReport ScanInvisible(string text)
    {
        int tags = 0, bidi = 0, zeroWidth = 0, selectors = 0, privateUse = 0;
        var decoded = new StringBuilder();
        var first = true;
        foreach (var rune in text.EnumerateRunes())
        {
            var v = rune.Value;
            if (v is >= 0xE0000 and <= 0xE007F)
            {
                tags++;
                if (v is >= 0xE0020 and <= 0xE007E)
                    decoded.Append((char)(v - 0xE0000));
            }
            else if (v is >= 0x202A and <= 0x202E or >= 0x2066 and <= 0x2069)
                bidi++;
            else if (v is >= 0x200B and <= 0x200F or >= 0x2060 and <= 0x2064 or 0x180E or 0x00AD || (v == 0xFEFF && !first))
                zeroWidth++;
            else if (v is >= 0xFE00 and <= 0xFE0F or >= 0xE0100 and <= 0xE01EF)
                selectors++;
            else if (v is >= 0xE000 and <= 0xF8FF or >= 0xF0000)
                privateUse++;
            first = false;
        }
        return new InvisibleCharReport(tags, bidi, zeroWidth, selectors, privateUse, decoded.ToString());
    }

    [GeneratedRegex(@"\b(?:https?|ftp)://[^\s'""<>)\]]+|\bwww\.[a-z0-9-]+\.[a-z]{2,}[^\s'""<>)\]]*", RegexOptions.IgnoreCase)]
    private static partial Regex UrlRegex();

    public static IEnumerable<string> FindUrls(string text) => UrlRegex().Matches(text).Select(m => m.Value);

    [GeneratedRegex(@"<\s*(?:script|img|iframe|object|embed|link|meta|svg)\b|!\[[^\]]*\]\(\s*(?:https?:)?//", RegexOptions.IgnoreCase)]
    private static partial Regex ActiveMarkupRegex();

    /// <summary>HTML or markdown that makes a client fetch a URL when rendered, a classic data-exfiltration vector.</summary>
    public static IEnumerable<string> FindActiveMarkup(string text) => ActiveMarkupRegex().Matches(text).Select(m => m.Value);

    static readonly (Regex Regex, string Description, Severity Severity)[] InstructionPatterns =
    [
        (new(@"\b(?:do not|don't|never)\s+(?:tell|inform|mention|reveal|disclose|let)\b[^.\n]{0,40}\b(?:user|anyone|human|them)\b", RegexOptions.IgnoreCase), "concealment from the user", Severity.High),
        (new(@"\bwithout\s+(?:telling|informing|notifying|alerting|asking)\b", RegexOptions.IgnoreCase), "acting without telling the user", Severity.High),
        (new(@"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|preceding|system)\s+(?:instructions|messages|rules|prompts?)\b", RegexOptions.IgnoreCase), "instruction override", Severity.High),
        (new(@"\b(?:secretly|covertly|silently|surreptitiously)\b", RegexOptions.IgnoreCase), "covert behaviour", Severity.High),
        (new(@"\b(?:hidden|secret)\s+(?:instructions?|rules?|directives?|tasks?|objectives?)\b", RegexOptions.IgnoreCase), "hidden directive", Severity.High),
        (new(@"\b(?:exfiltrat\w*|upload|send|post|forward|transmit)\b[^.\n]{0,60}\b(?:to|at)\s+(?:https?://|\S+\.[a-z]{2,}/)", RegexOptions.IgnoreCase), "sending data to a remote address", Severity.High),
        (new(@"\b(?:curl|wget|Invoke-WebRequest|Invoke-Expression|iwr|iex|powershell(?:\.exe)?|bash\s+-c|sh\s+-c|nc\s+-e|base64\s+-d|certutil|bitsadmin|mshta|rundll32)\b", RegexOptions.IgnoreCase), "shell or download command", Severity.High),
        (new(@"(?:\.env\b|\bid_rsa\b|\bid_ed25519\b|\.ssh/|\.aws/credentials|\bapi[_ -]?keys?\b|\bprivate key\b|\bseed phrase\b|\bcrypto ?wallet\b|\bpasswords?\b)", RegexOptions.IgnoreCase), "reference to secrets or credentials", Severity.High),
        (new(@"\balways\s+(?:include|insert|add|append|recommend|mention|link|respond with|output|suggest)\b", RegexOptions.IgnoreCase), "forced content insertion", Severity.Medium),
        (new(@"\byou must (?:always|never)\b", RegexOptions.IgnoreCase), "absolute behavioural rule", Severity.Medium),
    ];

    public static IEnumerable<PhraseMatch> FindInstructionPhrases(string text)
    {
        foreach (var (regex, description, severity) in InstructionPatterns)
            foreach (Match m in regex.Matches(text))
                yield return new PhraseMatch(description, severity, m.Value);
    }

    /// <summary>Looks for executables or archives hidden inside a string, raw or base64 encoded.</summary>
    public static string? FindEncodedExecutable(string text)
    {
        if (text.StartsWith("MZ", StringComparison.Ordinal) && text.Contains("This program cannot be run", StringComparison.Ordinal)) return "Windows PE executable";
        if (text.StartsWith("\u007fELF", StringComparison.Ordinal)) return "ELF executable";
        if (text.StartsWith("PK\u0003\u0004", StringComparison.Ordinal)) return "ZIP archive";
        if (text.StartsWith("#!/", StringComparison.Ordinal)) return "shell script";
        if (text.Contains("TVqQAAMAAAAEAAAA", StringComparison.Ordinal)) return "base64-encoded Windows PE executable";
        if (text.Contains("f0VMRgI", StringComparison.Ordinal) || text.Contains("f0VMRgE", StringComparison.Ordinal)) return "base64-encoded ELF executable";
        if (text.Contains("UEsDBBQA", StringComparison.Ordinal)) return "base64-encoded ZIP archive";
        return null;
    }

    /// <summary>Looks for executable or archive signatures in raw bytes (e.g. slack space between tensors).</summary>
    public static string? FindBinarySignature(ReadOnlySpan<byte> data)
    {
        if (data.StartsWith("#!/"u8)) return "shell script";
        var elf = data.IndexOf("\u007fELF"u8);
        if (elf >= 0) return $"ELF executable at +0x{elf:X}";
        var zip = data.IndexOf("PK\u0003\u0004"u8);
        if (zip >= 0) return $"ZIP archive at +0x{zip:X}";
        for (var i = data.IndexOf("MZ"u8); i >= 0 && i + 0x40 <= data.Length;)
        {
            var peOffset = BitConverter.ToInt32(data.Slice(i + 0x3C, 4));
            if (peOffset > 0 && i + peOffset + 4 <= data.Length && data.Slice(i + peOffset, 4).SequenceEqual("PE\0\0"u8))
                return $"Windows PE executable at +0x{i:X}";
            var next = data[(i + 2)..].IndexOf("MZ"u8);
            i = next < 0 ? -1 : i + 2 + next;
        }
        foreach (var magic in new[] { new byte[] { 0xCF, 0xFA, 0xED, 0xFE }, [0xCE, 0xFA, 0xED, 0xFE] })
        {
            var macho = data.IndexOf(magic);
            if (macho >= 0) return $"Mach-O executable at +0x{macho:X}";
        }
        return null;
    }

    [GeneratedRegex(@"^[A-Za-z0-9+/=_\-\s]+$")]
    private static partial Regex Base64Regex();

    /// <summary>Long, base64-looking, high-entropy text: a common way to smuggle a payload through metadata.</summary>
    public static bool LooksLikeEncodedBlob(string text) =>
        text.Length >= 512 && Base64Regex().IsMatch(text) && ShannonEntropy(text) >= 5.0;

    public static double ShannonEntropy(string text)
    {
        if (text.Length == 0) return 0;
        var counts = new Dictionary<char, int>();
        foreach (var c in text)
            counts[c] = counts.GetValueOrDefault(c) + 1;
        return -counts.Values.Sum(n => (double)n / text.Length * Math.Log2((double)n / text.Length));
    }

    public static string Truncate(string text, int max)
    {
        var flat = text.Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t");
        return flat.Length <= max ? flat : flat[..max] + "…";
    }

    public static int CountWords(string text) => WordRegex().Count(text);

    [GeneratedRegex(@"\p{L}{2,}")]
    private static partial Regex WordRegex();
}
