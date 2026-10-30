using ModelSafetyCheck.Core;

namespace ModelSafetyCheck.Rules;

public sealed class GgufScanContext(GgufFile file, Stream stream)
{
    public GgufFile File { get; } = file;

    /// <summary>The scanned file, for rules that need to look at bytes outside the header.</summary>
    public Stream Stream { get; } = stream;
}

public interface IGgufRule
{
    IEnumerable<Finding> Check(GgufScanContext context);
}

/// <summary>GGUF-S rules: header and tensor layout sanity. These catch files crafted to exploit runner parsers.</summary>
public sealed class StructuralRules : IGgufRule
{
    const int SlackScanBytes = 4 << 20;

    public IEnumerable<Finding> Check(GgufScanContext context)
    {
        var file = context.File;
        var findings = new List<Finding>();

        foreach (var group in file.Metadata.GroupBy(k => k.Key, StringComparer.Ordinal).Where(g => g.Count() > 1))
            findings.Add(new("S010", Severity.High, "Duplicate metadata key",
                $"Key '{group.Key}' appears {group.Count()} times. Different runners may read different copies, which can hide a malicious value such as a second chat template.",
                $"kv:{group.Key}"));

        if (!file.TensorInfoComplete)
            return findings;

        foreach (var group in file.Tensors.GroupBy(t => t.Name, StringComparer.Ordinal).Where(g => g.Count() > 1))
            findings.Add(new("S010", Severity.High, "Duplicate tensor name", $"Tensor '{group.Key}' appears {group.Count()} times.", $"tensor:{group.Key}"));

        var fileLength = (ulong)file.FileLength;
        var dataStart = (ulong)file.DataStart;
        var placed = new List<(GgufTensorInfo Tensor, ulong Start, ulong Size)>();
        var allSized = true;
        // One finding per unknown type: a file in a new format has hundreds of such tensors, which would bury everything else.
        var unknownTypes = new SortedDictionary<uint, List<string>>();

        foreach (var t in file.Tensors)
        {
            var location = $"tensor:{t.Name}";
            if (t.Dimensions.Length > 4)
                findings.Add(new("S004", Severity.High, "Too many tensor dimensions", $"Tensor has {t.Dimensions.Length} dimensions; GGML supports at most 4.", location));
            if (t.Dimensions.Length == 0 || t.Dimensions.Any(d => d == 0))
                findings.Add(new("S004", Severity.Medium, "Empty tensor dimension", $"Tensor has shape [{string.Join(", ", t.Dimensions)}].", location));

            if (!TryElementCount(t.Dimensions, out var elements))
            {
                findings.Add(new("S005", Severity.Critical, "Tensor size overflows",
                    $"Shape [{string.Join(", ", t.Dimensions)}] overflows a 64-bit element count. Runners that multiply these without checks compute a wrong buffer size.", location));
                allSized = false;
                continue;
            }
            if (!GgmlTypes.TryGet(t.Type, out var type))
            {
                (unknownTypes.TryGetValue(t.Type, out var names) ? names : unknownTypes[t.Type] = []).Add(t.Name);
                allSized = false;
                continue;
            }
            if (t.Dimensions.Length > 0 && t.Dimensions[0] % (ulong)type.BlockSize != 0)
            {
                findings.Add(new("S005", Severity.High, "Row size is not a whole number of blocks",
                    $"{type.Name} stores {type.BlockSize} values per block but the first dimension is {t.Dimensions[0]}.", location));
                allSized = false;
                continue;
            }
            if (t.Offset % file.Alignment != 0)
                findings.Add(new("S007", Severity.High, "Misaligned tensor offset", $"Offset {t.Offset} is not a multiple of the alignment ({file.Alignment}).", location));

            var size = elements / (ulong)type.BlockSize * (ulong)type.TypeSize;
            if (t.Offset > fileLength || dataStart > fileLength - t.Offset || size > fileLength - dataStart - t.Offset)
            {
                findings.Add(new("S008", Severity.Critical, "Tensor data extends beyond the file",
                    $"The tensor claims {size:N0} bytes at data offset {t.Offset:N0}, but the file is only {fileLength:N0} bytes. " +
                    "A runner that trusts these sizes reads memory past its buffer; the 'Bleeding Llama' Ollama bug leaked heap memory (API keys, prompts) this way.",
                    location));
                allSized = false;
                continue;
            }
            placed.Add((t, dataStart + t.Offset, size));
        }

        foreach (var (typeId, names) in unknownTypes)
            findings.Add(new("S006", Severity.Medium, "Unknown tensor type",
                $"Type {typeId} is not known to this scanner. It may be a new quantization format, or an invalid value meant to confuse a runner. " +
                $"{names.Count} tensor(s) use it: {string.Join(", ", names.Take(5))}{(names.Count > 5 ? ", ..." : ".")}",
                $"tensor-type:{typeId}"));

        if (allSized)
            CheckLayout(context, placed, findings);
        return findings;
    }

    void CheckLayout(GgufScanContext context, List<(GgufTensorInfo Tensor, ulong Start, ulong Size)> placed, List<Finding> findings)
    {
        var file = context.File;
        var cursor = (ulong)file.DataStart;
        (GgufTensorInfo Tensor, ulong Start, ulong Size)? previous = null;

        foreach (var p in placed.Where(p => p.Size > 0).OrderBy(p => p.Start))
        {
            if (previous is { } prev && p.Start < prev.Start + prev.Size)
                findings.Add(new("S009", Severity.Critical, "Overlapping tensors",
                    $"Tensor '{p.Tensor.Name}' overlaps '{prev.Tensor.Name}'. Writing one corrupts the other; legitimate files never do this.", $"tensor:{p.Tensor.Name}"));
            else if (p.Start > cursor && p.Start - cursor >= file.Alignment)
                CheckSlack(context, cursor, p.Start - cursor, "S011", $"Unused gap before tensor '{p.Tensor.Name}'", findings);

            cursor = Math.Max(cursor, GgufParser.AlignUp(p.Start + p.Size, file.Alignment));
            previous = p;
        }

        var fileLength = (ulong)file.FileLength;
        if (fileLength > cursor && fileLength - cursor >= file.Alignment)
            CheckSlack(context, cursor, fileLength - cursor, "S012", "Data after the last tensor", findings);
    }

    static void CheckSlack(GgufScanContext context, ulong start, ulong length, string ruleId, string title, List<Finding> findings)
    {
        var buffer = new byte[(int)Math.Min(length, SlackScanBytes)];
        context.Stream.Position = (long)start;
        context.Stream.ReadExactly(buffer);
        var location = $"offset 0x{start:X}";

        var signature = TextHeuristics.FindBinarySignature(buffer);
        if (signature is not null)
            findings.Add(new("M003", Severity.High, "Executable or archive hidden in unused space",
                $"Found a {signature} inside {length:N0} bytes that no tensor uses. Model files have no reason to carry executables.", location));

        var zeros = Array.TrueForAll(buffer, b => b == 0);
        findings.Add(new(ruleId, zeros ? Severity.Low : Severity.Medium, title,
            $"{length:N0} bytes are not used by any tensor{(zeros ? " (all zero)" : " and contain non-zero data")}. Unused space can carry hidden payloads.", location));
    }

    static bool TryElementCount(ulong[] dims, out ulong count)
    {
        count = 1;
        try
        {
            foreach (var d in dims)
                count = checked(count * d);
            return count <= long.MaxValue;
        }
        catch (OverflowException)
        {
            return false;
        }
    }
}

/// <summary>GGUF-M rules: payloads, encoded blobs and hidden characters in metadata values.</summary>
public sealed class MetadataRules : IGgufRule
{
    static readonly HashSet<string> KnownNamespaces = ["general", "tokenizer", "split", "quantize", "imatrix", "adapter", "clip", "mm"];

    public IEnumerable<Finding> Check(GgufScanContext context)
    {
        var file = context.File;
        var findings = new List<Finding>();
        var architecture = file.GetString("general.architecture");

        foreach (var kv in file.Metadata)
        {
            var location = $"kv:{kv.Key}";
            if (kv.Value is SkippedString skipped)
            {
                findings.Add(new("M001", Severity.High, "Metadata string too large to analyse",
                    $"The value is {skipped.Length:N0} bytes. Nothing legitimate in GGUF metadata needs a string this size.", location));
                continue;
            }
            if (TemplateRules.IsTemplateKey(kv.Key))
                continue; // Templates get their own, deeper analysis.

            if (kv.Value is string s)
                CheckString(kv.Key, s, location, findings);
            else if (kv.Value is GgufArray { Strings: { } strings } && !kv.Key.StartsWith("tokenizer.ggml.", StringComparison.Ordinal))
                foreach (var item in strings.Take(10_000))
                    CheckString(kv.Key, item, location, findings);
        }

        var unknown = file.Metadata.Select(k => k.Key.Split('.')[0])
            .Where(ns => !KnownNamespaces.Contains(ns) && ns != architecture)
            .Distinct()
            .ToList();
        if (unknown.Count > 0)
            findings.Add(new("M006", Severity.Info, "Unrecognised metadata namespaces",
                $"Keys outside the standard namespaces: {string.Join(", ", unknown.Take(20))}. Usually harmless, but runners ignore them, so they are a place to hide data.", null));

        return findings;
    }

    public static void CheckString(string key, string value, string location, List<Finding> findings)
    {
        if (value.Length > 64 * 1024 && !key.StartsWith("tokenizer.", StringComparison.Ordinal))
            findings.Add(new("M001", Severity.Medium, "Very large metadata string", $"The value is {value.Length:N0} characters.", location));

        var executable = TextHeuristics.FindEncodedExecutable(value);
        if (executable is not null)
            findings.Add(new("M003", Severity.High, "Executable content in metadata", $"The value looks like a {executable}.", location));
        else if (TextHeuristics.LooksLikeEncodedBlob(value))
            findings.Add(new("M002", Severity.Medium, "Encoded blob in metadata",
                $"A {value.Length:N0}-character base64-like value with high entropy. Encoded blobs are a common way to smuggle payloads.", location));

        var invisible = TextHeuristics.ScanInvisible(value);
        if (invisible.Any)
            findings.Add(new("M005", invisible.Severity, "Invisible Unicode in metadata", $"Found {invisible.Describe()}.", location));

        var urls = TextHeuristics.FindUrls(value).Distinct().ToList();
        if (urls.Count > 0)
            findings.Add(new("M004", key.StartsWith("general.", StringComparison.Ordinal) ? Severity.Info : Severity.Low, "URL in metadata",
                string.Join(", ", urls.Take(5)), location));
    }
}

/// <summary>GGUF-K rules: tokenizer consistency. Out-of-range token ids make runners index past their tables.</summary>
public sealed partial class TokenizerRules : IGgufRule
{
    static readonly string[] TokenIdKeys =
    [
        "tokenizer.ggml.bos_token_id", "tokenizer.ggml.eos_token_id", "tokenizer.ggml.padding_token_id", "tokenizer.ggml.unknown_token_id",
        "tokenizer.ggml.seperator_token_id", "tokenizer.ggml.separator_token_id", "tokenizer.ggml.cls_token_id", "tokenizer.ggml.mask_token_id",
        "tokenizer.ggml.eot_token_id", "tokenizer.ggml.eom_token_id",
    ];

    public IEnumerable<Finding> Check(GgufScanContext context)
    {
        var file = context.File;
        var tokens = file.GetArray("tokenizer.ggml.tokens");
        if (tokens is null)
            yield break;
        var vocab = tokens.Count;

        foreach (var key in TokenIdKeys)
        {
            var id = file.GetInteger(key);
            if (id is null)
                continue;
            if (id < 0)
                yield return new("K001", Severity.Low, "Negative special token id", $"{key} is {id}.", $"kv:{key}");
            else if ((ulong)id >= vocab)
                yield return new("K001", Severity.High, "Special token id outside the vocabulary",
                    $"{key} is {id} but the vocabulary has {vocab} tokens. Runners that trust it index past the token table.", $"kv:{key}");
        }

        foreach (var finding in CheckSpecialTokens(file, tokens))
            yield return finding;

        var embedding = file.Tensors.FirstOrDefault(t => t.Name == "token_embd.weight");
        if (embedding is { Dimensions.Length: >= 2 } && embedding.Dimensions[1] < vocab)
            yield return new("K002", Severity.High, "Vocabulary larger than the embedding table",
                $"The tokenizer has {vocab} tokens but token_embd.weight has only {embedding.Dimensions[1]} rows. Token ids past that read out of bounds.",
                "tensor:token_embd.weight");
    }
}

public sealed partial class TokenizerRules
{
    const int ControlToken = 3;
    const int UserDefinedToken = 4;

    /// <summary>
    /// K003: control and user-defined tokens are single ids the runner inserts verbatim. One whose text
    /// is a sentence or an instruction smuggles a whole prompt into "one token" that reviewers skip.
    /// </summary>
    static IEnumerable<Finding> CheckSpecialTokens(GgufFile file, GgufArray tokens)
    {
        var types = file.GetArray("tokenizer.ggml.token_type")?.Integers;
        if (types is null || tokens.Strings is null)
            yield break;

        var suspicious = new List<(string Text, Severity Severity, string Why)>();
        for (var i = 0; i < Math.Min(types.Count, tokens.Strings.Count); i++)
        {
            if (types[i] is not (ControlToken or UserDefinedToken))
                continue;
            var text = tokens.Strings[i];
            var phrase = TextHeuristics.FindInstructionPhrases(text).OrderByDescending(p => p.Severity).FirstOrDefault();
            var invisible = TextHeuristics.ScanInvisible(text);
            if (phrase is not null)
                suspicious.Add((text, phrase.Severity, phrase.Description));
            else if (invisible.Tags > 0 || invisible.Bidi > 0)
                suspicious.Add((text, Severity.High, invisible.Describe()));
            else if (TextHeuristics.FindUrls(text).Any())
                suspicious.Add((text, Severity.Medium, "contains a URL"));
            else if (TextHeuristics.CountWords(text) >= 6)
                suspicious.Add((text, Severity.Medium, "a whole sentence as one special token"));
        }

        if (suspicious.Count == 0)
            yield break;
        yield return new Finding("K003", suspicious.Max(s => s.Severity), "Special tokens that contain text or instructions",
            "Control/user-defined tokens are inserted as single ids, so text inside them is easy to miss: " +
            string.Join("", suspicious.Take(5).Select(s => $"\n  - {s.Why}: \"{TextHeuristics.Truncate(s.Text, 100)}\"")) +
            (suspicious.Count > 5 ? $"\n  (+{suspicious.Count - 5} more)" : ""),
            "kv:tokenizer.ggml.tokens");
    }
}

/// <summary>GGUF-T rules: finds every embedded chat template and runs <see cref="TemplateAnalyzer"/> on it.</summary>
public static class TemplateRules
{
    public static bool IsTemplateKey(string key) =>
        key == "tokenizer.chat_template" || key.StartsWith("tokenizer.chat_template.", StringComparison.Ordinal);
}
