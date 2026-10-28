using System.Text.Json;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using Microsoft.ML.Tokenizers;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Classifier;

/// <summary>
/// A DeBERTa-v3 sequence classifier exported to ONNX (default: protectai/deberta-v3-base-prompt-injection-v2,
/// Apache-2.0), run locally with ONNX Runtime on the CPU. Texts longer than the model's window are split
/// into overlapping chunks and the highest chunk score is used.
/// </summary>
public sealed class PromptInjectionClassifier : ITextClassifier, IDisposable
{
    const int MaxTokens = 512;
    const int ChunkTokens = 448;
    const int ChunkStride = 384;

    readonly InferenceSession _session;
    readonly SentencePieceTokenizer _tokenizer;
    readonly int _clsId, _sepId, _padId, _injectionLabel;
    readonly bool _needsTokenTypes;

    public string Name { get; }

    PromptInjectionClassifier(string directory)
    {
        var config = JsonDocument.Parse(File.ReadAllText(Path.Combine(directory, "config.json"))).RootElement;
        _injectionLabel = config.TryGetProperty("label2id", out var l2i) && l2i.TryGetProperty("INJECTION", out var inj) ? inj.GetInt32() : 1;
        Name = config.TryGetProperty("_name_or_path", out var n) && n.GetString() is { Length: > 0 } name ? name : "prompt-injection classifier";

        // DeBERTa-v3 reserves [PAD]=0, [CLS]=1, [SEP]=2, [UNK]=3; the actual ids come from tokenizer.json when present.
        (_padId, _clsId, _sepId) = (0, 1, 2);
        var tokenizerJson = Path.Combine(directory, "tokenizer.json");
        if (File.Exists(tokenizerJson))
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(tokenizerJson));
            foreach (var t in doc.RootElement.GetProperty("added_tokens").EnumerateArray())
            {
                var id = t.GetProperty("id").GetInt32();
                switch (t.GetProperty("content").GetString())
                {
                    case "[PAD]": _padId = id; break;
                    case "[CLS]": _clsId = id; break;
                    case "[SEP]": _sepId = id; break;
                }
            }
        }

        using var spm = File.OpenRead(Path.Combine(directory, "spm.model"));
        _tokenizer = SentencePieceTokenizer.Create(spm, false, false);

        var options = new SessionOptions { GraphOptimizationLevel = GraphOptimizationLevel.ORT_ENABLE_ALL, IntraOpNumThreads = Math.Max(1, Environment.ProcessorCount / 2) };
        _session = new InferenceSession(Path.Combine(directory, "model.onnx"), options);
        _needsTokenTypes = _session.InputMetadata.ContainsKey("token_type_ids");
    }

    public static string DefaultDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".modelcheck", "classifier");

    public static bool IsInstalled(string directory) =>
        new[] { "model.onnx", "spm.model", "config.json" }.All(f => File.Exists(Path.Combine(directory, f)));

    public static PromptInjectionClassifier Load(string directory) =>
        IsInstalled(directory)
            ? new PromptInjectionClassifier(directory)
            : throw new FileNotFoundException($"No classifier in {directory}. Run `modelcheck classifier download` first.");

    /// <summary>
    /// Loads the classifier, or explains why it cannot run. The ONNX Runtime library must sit next to modelcheck;
    /// without it Windows may find its own older copy (System32), which fails with a version error.
    /// </summary>
    public static PromptInjectionClassifier? TryLoad(string directory, out string? error)
    {
        try
        {
            error = null;
            return Load(directory);
        }
        catch (FileNotFoundException ex)
        {
            error = ex.Message;
        }
        catch (Exception ex) when (ex is TypeInitializationException or DllNotFoundException or EntryPointNotFoundException or BadImageFormatException or OnnxRuntimeException)
        {
            error = "The classifier needs the ONNX Runtime library that ships next to modelcheck (onnxruntime.dll / libonnxruntime.so / .dylib). " +
                    $"It is missing or a different version was found: {(ex.InnerException ?? ex).Message}";
        }
        return null;
    }

    public IReadOnlyList<int> Tokenize(string text) => _tokenizer.EncodeToIds(text, addBeginningOfSentence: false, addEndOfSentence: false);

    public IReadOnlyList<double> Score(IReadOnlyList<string> texts) => texts.Select(ScoreOne).ToList();

    double ScoreOne(string text)
    {
        var ids = Tokenize(text);
        var best = 0.0;
        for (var start = 0; ; start += ChunkStride)
        {
            var chunk = ids.Skip(start).Take(ChunkTokens).ToList();
            best = Math.Max(best, Run(chunk));
            if (start + ChunkTokens >= ids.Count) break;
        }
        return best;
    }

    double Run(List<int> tokens)
    {
        var length = Math.Min(tokens.Count + 2, MaxTokens);
        var inputIds = new DenseTensor<long>([1, length]);
        var mask = new DenseTensor<long>([1, length]);
        inputIds[0, 0] = _clsId;
        for (var i = 0; i < length - 2; i++) inputIds[0, i + 1] = tokens[i];
        inputIds[0, length - 1] = _sepId;
        for (var i = 0; i < length; i++) mask[0, i] = 1;

        var inputs = new List<NamedOnnxValue>
        {
            NamedOnnxValue.CreateFromTensor("input_ids", inputIds),
            NamedOnnxValue.CreateFromTensor("attention_mask", mask),
        };
        if (_needsTokenTypes)
            inputs.Add(NamedOnnxValue.CreateFromTensor("token_type_ids", new DenseTensor<long>([1, length])));

        using var results = _session.Run(inputs);
        var logits = results[0].AsTensor<float>().ToArray();
        var max = logits.Max();
        var exp = logits.Select(l => Math.Exp(l - max)).ToArray();
        return exp[_injectionLabel] / exp.Sum();
    }

    public void Dispose() => _session.Dispose();
}
