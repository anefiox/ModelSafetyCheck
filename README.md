# ModelSafetyCheck

`modelcheck` scans local AI models and setups for the attacks that code-execution scanners miss:
files that *instruct* rather than *execute*.

Existing model scanners answer one question: will this file run code when loaded? Newer attacks don't
need to. A GGUF's chat template is Jinja code that runs on every prompt and can hide trigger-activated
instructions; malformed headers can make a runner leak its own memory; a runner exposed on the network
lets anyone rewrite templates behind your back; and an agent that can read your `.env` turns a
backdoored model into a credential stealer. `modelcheck` checks all five layers of a local setup:

| Layer | What | Command |
|---|---|---|
| L1 | The model file | `scan`, `local`, `repo` |
| L2 | The chat template (inside the GGUF, or overridden by Ollama / LM Studio) | `scan`, `local`, `repo`, `watch` |
| L3 | The runner (Ollama, LM Studio, llama-cpp-python, SGLang, vLLM) | `audit` |
| L4 | Network exposure (`OLLAMA_HOST`, open ports, Docker) | `audit` |
| L5 | What an agent can reach (secrets in its working directory) | `audit --agent-dir` |

> **A clean result does not mean a model is safe.** Backdoors trained into the weights cannot be found
> by static scanning. `modelcheck` finds known file, template and setup problems and helps you limit
> what a compromised model can reach.

## Usage

```bash
modelcheck repo bartowski/Llama-3.2-3B-Instruct-GGUF   # before downloading: files, card, publisher, each GGUF's template (header only)
modelcheck scan model.gguf                              # a file, or a folder of *.gguf
modelcheck local                                        # everything in Ollama, LM Studio, llama.cpp and HF caches
modelcheck local --dump-template                        # ...and print the templates so you can read them
modelcheck audit --agent-dir ~/my-agent --probe         # runner versions, network exposure, Docker, secrets, risk rating
modelcheck watch                                        # first run: baseline; later runs: templates changed without a model update
modelcheck watch --print-schedule                       # how an hourly check would be scheduled (--install-schedule to do it)
```

Common options: `--format text|json|sarif`, `--min-severity info|low|medium|high|critical`, `--no-color`.
Exit codes: `0` clean, `1` warnings (low/medium), `2` high or critical findings, `3` scan error.

`repo` uses `HF_TOKEN` for gated repos (sent only to huggingface.co). Everything else runs offline.

## What it checks

| Area | Rules | Examples |
|---|---|---|
| File structure | S001–S013 | lying string/array lengths, impossible counts, tensors past end of file ("Bleeding Llama" class), overlaps, hidden data in gaps or after the last tensor |
| Metadata | M001–M006 | executables or base64 payloads in strings, invisible Unicode, URLs |
| Tokenizer | K001–K003 | special-token ids outside the vocabulary, vocabulary larger than the embedding table, instructions hidden in special tokens |
| Chat templates | T001–T011 | Jinja sandbox escapes (CVE-2024-34359 "Llama Drama"), trigger phrases, date/random conditions, hidden instructions, exfiltration links, Unicode tag smuggling, diff against 41 official templates |
| Ollama | O001–O005 | Ollama's own template and system layers (what actually runs), path-traversal digests |
| Runner & network | A001–A007 | known-vulnerable versions, `OLLAMA_HOST=0.0.0.0`, `OLLAMA_ORIGINS=*`, open ports, Docker port publishing, unauthenticated access |
| Agent | G001–G003 | readable secrets (values never printed), per-layer risk rating |
| Hugging Face repo | H001–H009 | executables and lure instructions in the card, publisher tier, lineage, file template differing from the displayed one, pickle files |
| Template drift | W001–W003 | template or system prompt changed while the weights did not |

Templates are lexed and analysed, never rendered. Reference data (vulnerable versions, official templates,
trusted publishers) lives in [`data/`](data) with sources, and a newer copy in `~/.modelcheck/data` overrides
the built-in one. See [BUILD_PLAN.md](BUILD_PLAN.md) for every rule and the roadmap.

## Install

```bash
dotnet tool install --global ModelSafetyCheck      # once published; portable, needs the .NET 10 runtime
```

Or download a native single binary from the GitHub releases (built by `.github/workflows/release.yml`).

## Building

Requires the .NET 10 SDK.

```bash
dotnet test
dotnet publish src/ModelSafetyCheck.Cli -c Release -r linux-x64   # native binary: win-x64, win-arm64, linux-x64, linux-arm64, osx-arm64
dotnet pack src/ModelSafetyCheck.Cli -c Release                     # dotnet tool package
dotnet run --project tools/TemplateDbBuilder                        # refresh data/known-templates.json from Hugging Face
```

Native AOT on Windows needs the Visual Studio C++ build tools with `vswhere.exe` on PATH.

## Licence

MIT
