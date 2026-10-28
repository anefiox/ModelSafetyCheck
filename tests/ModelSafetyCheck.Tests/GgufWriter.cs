using System.Text;
using ModelSafetyCheck.Core;

namespace ModelSafetyCheck.Tests;

/// <summary>A string whose length prefix lies about how many bytes follow.</summary>
public sealed record LyingString(string Text, ulong DeclaredLength);

/// <param name="OmitData">Write the tensor info but no data, so its declared size points past the end of the file.</param>
public sealed record TensorSpec(string Name, ulong[] Dimensions, uint Type, ulong? Offset = null, bool OmitData = false);

/// <summary>
/// Writes GGUF v3 files for tests. It writes valid files by default and has hooks for producing
/// deliberately malformed ones (lying counts, lengths, offsets, trailing payloads).
/// </summary>
public sealed class GgufWriter
{
    readonly List<(string Key, GgufValueType Type, object Value)> _kvs = [];
    readonly List<TensorSpec> _tensors = [];

    public uint Magic { get; set; } = GgufParser.Magic;
    public uint Version { get; set; } = 3;
    public ulong? TensorCountOverride { get; set; }
    public ulong? KvCountOverride { get; set; }
    public ulong Alignment { get; set; } = 32;
    public byte[] TrailingData { get; set; } = [];

    public GgufWriter Add(string key, string value) => Add(key, GgufValueType.String, value);
    public GgufWriter Add(string key, uint value) => Add(key, GgufValueType.UInt32, value);
    public GgufWriter Add(string key, GgufValueType type, object value)
    {
        _kvs.Add((key, type, value));
        return this;
    }

    public GgufWriter AddStringArray(string key, IEnumerable<string> values) =>
        Add(key, GgufValueType.Array, (GgufValueType.String, values.Cast<object>().ToArray()));

    public GgufWriter AddTensor(string name, ulong[] dims, uint type = 0, ulong? offset = null, bool omitData = false)
    {
        _tensors.Add(new TensorSpec(name, dims, type, offset, omitData));
        return this;
    }

    /// <summary>A small, valid model: architecture, tokenizer, one F32 embedding tensor and an optional template.</summary>
    public static GgufWriter Minimal(string? chatTemplate = null, int vocab = 4)
    {
        var writer = new GgufWriter()
            .Add("general.architecture", "llama")
            .Add("general.name", "test-model")
            .AddStringArray("tokenizer.ggml.tokens", Enumerable.Range(0, vocab).Select(i => $"tok{i}"))
            .Add("tokenizer.ggml.bos_token_id", 0u)
            .Add("tokenizer.ggml.eos_token_id", 1u)
            .AddTensor("token_embd.weight", [8, (ulong)vocab]);
        if (chatTemplate is not null)
            writer.Add("tokenizer.chat_template", chatTemplate);
        return writer;
    }

    public byte[] Build()
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write(Magic);
        w.Write(Version);
        w.Write(TensorCountOverride ?? (ulong)_tensors.Count);
        w.Write(KvCountOverride ?? (ulong)_kvs.Count);

        foreach (var (key, type, value) in _kvs)
        {
            WriteString(w, key);
            w.Write((uint)type);
            WriteValue(w, type, value);
        }

        var sizes = _tensors.Select(TensorBytes).ToList();
        ulong next = 0;
        var offsets = new List<ulong>();
        for (var i = 0; i < _tensors.Count; i++)
        {
            var offset = _tensors[i].Offset ?? next;
            offsets.Add(offset);
            next = Math.Max(next, GgufParser.AlignUp(offset + sizes[i], Alignment));
        }

        for (var i = 0; i < _tensors.Count; i++)
        {
            var t = _tensors[i];
            WriteString(w, t.Name);
            w.Write((uint)t.Dimensions.Length);
            foreach (var d in t.Dimensions) w.Write(d);
            w.Write(t.Type);
            w.Write(offsets[i]);
        }

        Pad(w, Alignment);
        var dataStart = (ulong)ms.Position;
        for (var i = 0; i < _tensors.Count; i++)
        {
            if (_tensors[i].OmitData) continue;
            var end = dataStart + offsets[i] + sizes[i];
            if ((ulong)ms.Length < end) ms.SetLength((long)end);
        }
        ms.Position = ms.Length;
        if (_tensors.Count > 0)
            Pad(w, Alignment);
        w.Write(TrailingData);
        w.Flush();
        return ms.ToArray();
    }

    public MemoryStream BuildStream() => new(Build());

    static ulong TensorBytes(TensorSpec t)
    {
        if (!GgmlTypes.TryGet(t.Type, out var info)) return 0;
        try
        {
            var elements = t.Dimensions.Aggregate(1UL, (a, d) => checked(a * d));
            return elements / (ulong)info.BlockSize * (ulong)info.TypeSize;
        }
        catch (OverflowException)
        {
            return 0;
        }
    }

    static void Pad(BinaryWriter w, ulong alignment)
    {
        while ((ulong)w.BaseStream.Position % alignment != 0) w.Write((byte)0);
    }

    static void WriteString(BinaryWriter w, string s)
    {
        var bytes = Encoding.UTF8.GetBytes(s);
        w.Write((ulong)bytes.Length);
        w.Write(bytes);
    }

    static void WriteValue(BinaryWriter w, GgufValueType type, object value)
    {
        switch (value)
        {
            case LyingString lie:
                var bytes = Encoding.UTF8.GetBytes(lie.Text);
                w.Write(lie.DeclaredLength);
                w.Write(bytes);
                return;
            case ValueTuple<GgufValueType, object[]> (var elementType, var items):
                w.Write((uint)elementType);
                w.Write((ulong)items.Length);
                foreach (var item in items) WriteValue(w, elementType, item);
                return;
        }

        switch (type)
        {
            case GgufValueType.String: WriteString(w, (string)value); break;
            case GgufValueType.UInt32: w.Write(Convert.ToUInt32(value)); break;
            case GgufValueType.Int32: w.Write(Convert.ToInt32(value)); break;
            case GgufValueType.UInt64: w.Write(Convert.ToUInt64(value)); break;
            case GgufValueType.UInt8: w.Write(Convert.ToByte(value)); break;
            case GgufValueType.Bool: w.Write((bool)value); break;
            case GgufValueType.Float32: w.Write(Convert.ToSingle(value)); break;
            default: w.Write(Convert.ToUInt32(value)); break; // lets tests write bogus type ids
        }
    }
}
