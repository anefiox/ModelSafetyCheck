using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using ModelSafetyCheck.Core;

namespace ModelSafetyCheck.Rules;

/// <summary>
/// Rules PK001–PK004: static analysis of Python pickles (raw .pkl, legacy torch files, and the data.pkl inside
/// PyTorch zip checkpoints). Pickle runs code by design: every GLOBAL/STACK_GLOBAL import is collected
/// without executing anything and compared with what a model checkpoint legitimately needs.
/// </summary>
public static class PickleScanner
{
    const long MaxPickleBytes = 256L << 20;

    /// <summary>Imports a weights file legitimately makes. Anything else is unusual; the dangerous list is worse.</summary>
    static readonly HashSet<string> SafeImports =
    [
        "collections.OrderedDict", "collections.defaultdict", "torch._utils._rebuild_tensor", "torch._utils._rebuild_tensor_v2", "torch._utils._rebuild_parameter",
        "torch._utils._rebuild_parameter_with_state", "torch._utils._rebuild_qtensor", "torch._utils._rebuild_sparse_tensor", "torch._utils._rebuild_device_tensor_from_numpy",
        "torch._utils._rebuild_meta_tensor_no_storage", "torch._utils._rebuild_wrapper_subclass", "torch._tensor._rebuild_from_type_v2", "torch.Size", "torch.device", "torch.dtype",
        "torch.FloatStorage", "torch.HalfStorage", "torch.BFloat16Storage", "torch.DoubleStorage", "torch.LongStorage", "torch.IntStorage", "torch.ShortStorage", "torch.CharStorage",
        "torch.ByteStorage", "torch.BoolStorage", "torch.storage.UntypedStorage", "torch.storage._load_from_bytes", "torch.float16", "torch.float32", "torch.bfloat16", "torch.int64",
        "torch.nn.parameter.Parameter", "numpy.core.multiarray._reconstruct", "numpy._core.multiarray._reconstruct", "numpy.ndarray", "numpy.dtype", "numpy.core.multiarray.scalar",
        "numpy._core.multiarray.scalar", "builtins.set", "builtins.frozenset", "builtins.slice", "builtins.complex", "builtins.bytearray", "__builtin__.set", "_codecs.encode",
        "argparse.Namespace", "transformers.training_args.TrainingArguments",
    ];

    static readonly HashSet<string> DangerousModules =
    [
        "os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "runpy", "pty", "webbrowser", "requests", "urllib", "urllib2", "urllib.request", "http", "http.client",
        "httplib", "ftplib", "telnetlib", "smtplib", "asyncio", "code", "commands", "importlib", "pickle", "_pickle", "marshal", "ctypes", "multiprocessing", "pip", "setuptools",
        "distutils", "tempfile", "glob", "pathlib", "io", "zipimport", "bdb", "pdb", "timeit", "trace", "venv", "aiohttp", "httpx", "paramiko", "torch.hub", "torch.load",
    ];

    static readonly HashSet<string> DangerousBuiltins = ["eval", "exec", "compile", "open", "__import__", "getattr", "setattr", "delattr", "input", "breakpoint", "apply", "execfile", "file", "globals", "vars"];

    public static readonly HashSet<string> Extensions = new(StringComparer.OrdinalIgnoreCase) { ".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".joblib" };

    public static void Scan(Stream stream, ScanReport report)
    {
        Span<byte> magic = stackalloc byte[4];
        stream.Position = 0;
        var read = stream.ReadAtLeast(magic, 4, throwOnEndOfStream: false);
        stream.Position = 0;

        if (read == 4 && magic.SequenceEqual("PK\u0003\u0004"u8))
        {
            try
            {
                using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
                var pickles = zip.Entries.Where(e => e.FullName.EndsWith(".pkl", StringComparison.OrdinalIgnoreCase)).ToList();
                if (pickles.Count == 0)
                    report.Findings.Add(new Finding("PK004", Severity.Info, "Zip archive without a pickle", "No .pkl entry inside; not a PyTorch checkpoint.", null));
                foreach (var entry in pickles.Take(16))
                {
                    if (entry.Length > MaxPickleBytes) { report.Findings.Add(new Finding("PK004", Severity.Medium, "Pickle too large to analyse", $"{entry.FullName} is {entry.Length:N0} bytes.", entry.FullName)); continue; }
                    using var inner = entry.Open();
                    using var buffer = new MemoryStream();
                    inner.CopyTo(buffer);
                    buffer.Position = 0;
                    Analyze(buffer, entry.FullName, report);
                }
            }
            catch (InvalidDataException ex)
            {
                report.Findings.Add(new Finding("PK004", Severity.Medium, "Corrupt zip archive", ex.Message, null));
            }
            return;
        }

        // Raw pickles start with PROTO (protocol 2+) or, for protocols 0/1, a container or GLOBAL opcode.
        if (read == 0 || magic[0] is not (0x80 or (byte)'(' or (byte)']' or (byte)'}' or (byte)'c'))
        {
            report.Findings.Add(new Finding("PK004", Severity.Info, "Not a pickle", "The file is neither a pickle nor a PyTorch zip checkpoint, so it was not analysed.", null));
            return;
        }
        Analyze(stream, "pickle", report);
    }

    static void Analyze(Stream stream, string location, ScanReport report)
    {
        var (imports, error) = ReadImports(stream);
        var dangerous = imports.Where(IsDangerous).Distinct().ToList();
        var unusual = imports.Where(i => !IsDangerous(i) && !SafeImports.Contains(i) && !i.StartsWith("torch.", StringComparison.Ordinal) && !i.StartsWith("numpy.", StringComparison.Ordinal)).Distinct().ToList();

        if (dangerous.Count > 0)
            report.Findings.Add(new Finding("PK001", Severity.Critical, "Pickle imports code that runs on load",
                $"Loading this file (torch.load, pickle.load, joblib.load) calls: {string.Join(", ", dangerous.Take(10))}. This is how malicious checkpoints execute commands. Do not load it; use a safetensors or GGUF version instead.",
                location));
        if (unusual.Count > 0)
            report.Findings.Add(new Finding("PK002", Severity.Medium, "Pickle imports unusual objects",
                $"Imports outside the usual torch/numpy rebuild functions: {string.Join(", ", unusual.Take(10))}. Not necessarily malicious, but each one is code that runs on load.", location));
        if (error is not null)
            report.Findings.Add(new Finding("PK003", Severity.Medium, "Pickle could not be fully analysed", $"{error}. Imports after this point were not checked.", location));
        report.Findings.Add(new Finding("PK004", Severity.Info, "Pickle-based weights",
            $"{imports.Distinct().Count()} distinct import(s). Pickle runs code by design; prefer safetensors or GGUF, which cannot.", location));
    }

    static bool IsDangerous(string import)
    {
        var dot = import.LastIndexOf('.');
        var module = dot < 0 ? import : import[..dot];
        var name = dot < 0 ? "" : import[(dot + 1)..];
        if (module is "builtins" or "__builtin__" or "__builtins__") return DangerousBuiltins.Contains(name);
        if (module is "operator" && name is "attrgetter" or "methodcaller") return true;
        return DangerousModules.Contains(module) || DangerousModules.Any(m => module.StartsWith(m + ".", StringComparison.Ordinal));
    }

    /// <summary>Walks pickle opcodes (protocols 0–5) and collects module.name imports. Never executes anything.</summary>
    public static (List<string> Imports, string? Error) ReadImports(Stream s)
    {
        var imports = new List<string>();
        var strings = new List<string>();   // recent string pushes, for STACK_GLOBAL
        var memo = new Dictionary<long, string>();
        long nextMemo = 0;
        var start = s.Position;

        string Line()
        {
            var b = new List<byte>();
            int c;
            while ((c = s.ReadByte()) is not (-1 or '\n')) { b.Add((byte)c); if (b.Count > 4096) throw new InvalidDataException("line too long"); }
            if (c == -1) throw new EndOfStreamException();
            return Encoding.UTF8.GetString(b.ToArray()).TrimEnd('\r');
        }
        byte[] Bytes(long n)
        {
            if (n < 0 || n > MaxPickleBytes || s.Position + n > s.Length) throw new InvalidDataException("length beyond end of data");
            var b = new byte[n];
            s.ReadExactly(b);
            return b;
        }
        void Skip(long n)
        {
            if (n < 0 || s.Position + n > s.Length) throw new InvalidDataException("length beyond end of data");
            s.Position += n;
        }
        uint U32() { Span<byte> b = stackalloc byte[4]; s.ReadExactly(b); return BinaryPrimitives.ReadUInt32LittleEndian(b); }
        ulong U64() { Span<byte> b = stackalloc byte[8]; s.ReadExactly(b); return BinaryPrimitives.ReadUInt64LittleEndian(b); }
        int U8() => s.ReadByte() is var v and >= 0 ? v : throw new EndOfStreamException();
        void PushString(string v) { strings.Add(v); if (strings.Count > 8) strings.RemoveAt(0); }

        try
        {
            while (s.Position - start < MaxPickleBytes)
            {
                var op = s.ReadByte();
                if (op == -1) return (imports, null);
                switch (op)
                {
                    case '.': // STOP. Legacy torch files are several pickles in a row (magic, version, sys info, model).
                        if (s.Position < s.Length && s.ReadByte() == 0x80) { s.Position--; break; }
                        return (imports, null);
                    case '(' or '0' or '1' or '2' or 'N' or 'Q' or 'R' or 'a' or 'b' or 'd' or '}' or 'e' or 'l' or ']' or 'o' or 's' or 't' or ')' or 'u'
                        or 0x81 or 0x85 or 0x86 or 0x87 or 0x88 or 0x89 or 0x8f or 0x90 or 0x91 or 0x92 or 0x97 or 0x98:
                        break;
                    case 'F' or 'I' or 'L' or 'P': Line(); break;
                    case 'g': if (long.TryParse(Line(), out var gi) && memo.TryGetValue(gi, out var gs)) PushString(gs); break;
                    case 'p': if (long.TryParse(Line(), out var pi) && strings.Count > 0) memo[pi] = strings[^1]; break;
                    case 'S': PushString(Line().Trim('\'', '"')); break;
                    case 'V': PushString(Line()); break;
                    case 'J': Skip(4); break;
                    case 'K': Skip(1); break;
                    case 'M': Skip(2); break;
                    case 'G': Skip(8); break;
                    case 'T': PushString(Encoding.Latin1.GetString(Bytes(U32()))); break;
                    case 'U': PushString(Encoding.Latin1.GetString(Bytes(U8()))); break;
                    case 'X': PushString(Encoding.UTF8.GetString(Bytes(U32()))); break;
                    case 0x8c: PushString(Encoding.UTF8.GetString(Bytes(U8()))); break;
                    case 0x8d: PushString(Encoding.UTF8.GetString(Bytes((long)U64()))); break;
                    case 'B': Skip(U32()); break;
                    case 'C': Skip(U8()); break;
                    case 0x8e or 0x96: Skip((long)U64()); break;
                    case 'c' or 'i': imports.Add($"{Line()}.{Line()}"); break;
                    case 0x93:
                        if (strings.Count >= 2) imports.Add($"{strings[^2]}.{strings[^1]}");
                        else imports.Add("(unresolved STACK_GLOBAL)");
                        break;
                    case 'h': if (memo.TryGetValue(U8(), out var hs)) PushString(hs); break;
                    case 'j': if (memo.TryGetValue(U32(), out var js)) PushString(js); break;
                    case 'q': { var k = U8(); if (strings.Count > 0) memo[k] = strings[^1]; break; }
                    case 'r': { var k = U32(); if (strings.Count > 0) memo[k] = strings[^1]; break; }
                    case 0x94: if (strings.Count > 0) memo[nextMemo] = strings[^1]; nextMemo++; break;
                    case 0x80: Skip(1); break;           // PROTO
                    case 0x95: Skip(8); break;           // FRAME
                    case 0x82: Skip(1); break;           // EXT1
                    case 0x83: Skip(2); break;           // EXT2
                    case 0x84: Skip(4); break;           // EXT4
                    case 0x8a: Skip(U8()); break;        // LONG1
                    case 0x8b: Skip(U32()); break;       // LONG4
                    default: return (imports, $"Unknown opcode 0x{op:X2} at offset {s.Position - start - 1}");
                }
            }
            return (imports, "Pickle larger than the analysis limit");
        }
        catch (Exception ex) when (ex is EndOfStreamException or InvalidDataException)
        {
            return (imports, ex is EndOfStreamException ? "Pickle ended unexpectedly" : ex.Message);
        }
    }
}
