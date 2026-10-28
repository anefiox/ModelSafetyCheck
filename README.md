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
modelcheck repo ollama:llama3.2:1b                      # before `ollama pull`: template layer + GGUF header from the registry
modelcheck scan ./models                                # .gguf, .safetensors, .onnx, pickle checkpoints, tokenizer_config.json, chat_template.jinja
modelcheck explain model.gguf                           # the exact prompt the model receives, and what trigger phrases/dates change
modelcheck explain ollama:llama3.2:1b                   # same for an Ollama template layer (Go templates)
modelcheck local                                        # everything in Ollama, LM Studio, llama.cpp and HF caches
modelcheck local --dump-template                        # ...and print the templates so you can read them
modelcheck local --online --hash                        # ...and check each model's publisher, lineage and sha256 against Hugging Face
modelcheck audit --agent-dir ~/my-agent --probe         # runner versions, network exposure, Docker, MCP tools, secrets, risk rating
modelcheck watch --notify                               # first run: baseline; later runs: templates changed without a model update
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
| Chat templates | T001–T014 | Jinja sandbox escapes (CVE-2024-34359 "Llama Drama"), trigger phrases, date/random conditions, hidden instructions, exfiltration links, Unicode tag smuggling, diff against 62 official templates (including earlier versions), and **rendered evidence**: the template is run in a sandbox with and without each suspected trigger |
| Other formats | F001–F006, PK001–PK004, OX001–OX005 | safetensors header/offset checks; pickle checkpoints (raw, legacy torch, PyTorch zip) analysed opcode by opcode for imports like `os.system`; ONNX external-data path traversal (incl. symlinks) and custom operators |
| Ollama | O001–O005 | Ollama's own template and system layers (what actually runs), path-traversal digests |
| Runner & network | A001–A008 | known-vulnerable versions, `OLLAMA_HOST=0.0.0.0`, `OLLAMA_ORIGINS=*`, open ports and the process behind them, Docker port publishing, unauthenticated access, MCP tools given to local models |
| Agent | G001–G004 | readable secrets (values never printed), file/shell + network tool combinations, per-layer risk rating |
| Provenance | P001–P003 | `local --online`: installed file still matches its Hugging Face upload (size / sha256) |
| Hugging Face repo | H001–H009 | executables and lure instructions in the card, publisher tier, lineage, file template differing from the displayed one, pickle files |
| Template drift | W001–W003 | template or system prompt changed while the weights did not |

False positives are measured, not guessed: every official template in the database must analyse clean, and
`tools/TemplateCorpus` runs all rules over the templates of the 1,000 most-downloaded GGUF repos (currently 6.5% of
distinct templates get any warning, about 4% Medium or above, mostly unusual community templates worth a look).

Templates are never run by a real Jinja or Go engine. `explain` and rule T013 use modelcheck's own renderers (Jinja and Go text/template), which
only sees plain data (strings, numbers, lists, dicts) and whitelisted helpers, has no reflection, file, network or
process access, and caps steps, output and recursion. It renders all 62 official templates (and Ollama's own Go templates) and 96% of the 352
distinct templates in the top 1,000 GGUF repos; CI compares its output with real jinja2 byte for byte.

Reference data (vulnerable versions, official templates, trusted publishers) lives in [`data/`](data) with sources,
and a newer copy in `~/.modelcheck/data` overrides the built-in one. See [docs/rules.md](docs/rules.md) for every rule,
[docs/hardening.md](docs/hardening.md) for the five-layer hardening guide, and [BUILD_PLAN.md](BUILD_PLAN.md) for the roadmap.

## GitHub Action

```yaml
permissions:
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: <owner>/ModelSafetyCheck@v0.3.0
    with:
      command: scan          # or: repo
      args: models/          # or: bartowski/Llama-3.2-3B-Instruct-GGUF ollama:llama3.2
      fail-on: high
```

Findings appear in the repository's code scanning alerts (SARIF).

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
dotnet run --project tools/TemplateCorpus -- 1000                   # false-positive benchmark over the top GGUF repos
dotnet run --project tools/Fuzz -- --seed corpus                    # seed corpus for the SharpFuzz harness (see tools/Fuzz/Program.cs)
```

Native AOT on Windows needs the Visual Studio C++ build tools with `vswhere.exe` on PATH.

## Licence

MIT
