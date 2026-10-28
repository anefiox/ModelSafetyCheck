# ModelSafetyCheck

`modelcheck` scans local AI models and setups for the attacks that code-execution scanners miss:
files that *instruct* rather than *execute*.

Existing model scanners answer one question: will this file run code when loaded? Newer attacks don't
need to. A GGUF's chat template is Jinja code that runs on every prompt and can hide trigger-activated
instructions; malformed headers can make a runner leak its own memory; and a runner exposed on the
network lets anyone rewrite templates behind your back. `modelcheck` looks at those layers.

> **A clean result does not mean a model is safe.** Backdoors trained into the weights cannot be found
> by static scanning. `modelcheck` finds known file, template and setup problems and helps you limit
> what a compromised model can reach.

## Usage

```bash
modelcheck scan model.gguf             # one file
modelcheck scan ~/models               # every *.gguf under a folder
modelcheck local                       # everything installed in Ollama and LM Studio
modelcheck local --dump-template       # also print the templates so you can read them
modelcheck scan model.gguf --format json --min-severity medium
```

Exit codes: `0` clean, `1` warnings (low/medium), `2` high or critical findings, `3` scan error.

## What it checks (phase 1)

| Area | Rules | Examples |
|---|---|---|
| File structure | S001–S013 | lying string/array lengths, impossible counts, tensors past end of file ("Bleeding Llama" class), overlaps, hidden data in gaps or after the last tensor |
| Metadata | M001–M006 | executables or base64 payloads in strings, invisible Unicode, URLs |
| Tokenizer | K001–K002 | special-token ids outside the vocabulary, vocabulary larger than the embedding table |
| Chat templates | T001–T011 | Jinja sandbox escapes (CVE-2024-34359 "Llama Drama"), trigger phrases, date/random conditions, hidden instructions, exfiltration links, Unicode tag smuggling |
| Ollama | O001–O004 | Ollama's own template and system layers (the template that actually runs), path-traversal digests |

Templates are lexed and analysed, never rendered. See [BUILD_PLAN.md](BUILD_PLAN.md) for every rule and the roadmap
(`audit` for runner versions and network exposure, `repo` for pre-download checks, `watch` for template drift).

## Building

Requires the .NET 10 SDK.

```bash
dotnet test
dotnet publish src/ModelSafetyCheck.Cli -c Release -r linux-x64   # or win-x64, osx-arm64, linux-arm64
```

The publish produces a single native executable (Native AOT). On Windows this needs the Visual Studio C++
build tools.

## Licence

MIT
