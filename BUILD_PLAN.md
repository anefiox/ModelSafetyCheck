# ModelSafetyCheck — Build Plan

Open-source, cross-platform scanner for local-AI setups. It treats a local model setup as
five layers, each with its own threat model:

| Layer | What | Threat examples | Command |
|---|---|---|---|
| L1 | The model file (GGUF) | Malformed headers that exploit runner parsers (e.g. "Bleeding Llama" lying tensor sizes), payloads hidden in metadata or slack space | `scan`, `local` |
| L2 | The chat template (Jinja inside the GGUF, or overridden by the runner) | SSTI → RCE (llama-cpp-python "Llama Drama" CVE-2024-34359, SGLang 2026), poisoned templates with trigger-activated hidden instructions (Pillar Security), template rewritten after install via the runner API | `scan`, `local`, `watch`, `repo` |
| L3 | The runner (Ollama, LM Studio, llama.cpp, vLLM, SGLang) | Known-vulnerable versions, unsigned auto-update, path traversal | `audit` |
| L4 | The port / network exposure | `OLLAMA_HOST=0.0.0.0`, Docker `-p` bypassing ufw, no auth, DNS rebinding | `audit` |
| L5 | Weights + tools (agents) | Backdoored fine-tunes with trigger phrases (ProjectDiscovery), abliterated/merged models with unknown lineage, secrets reachable by the agent | `repo`, `audit --agent-dir` |

**Non-goal / honesty statement (must be in README):** weight backdoors cannot be detected by static
scanning. A clean result means "no known file/template/setup issue found", never "this model is safe".
The tool reduces blast radius and surfaces provenance; it does not certify weights.

## Principles

- **Never execute untrusted content.** Templates are lexed/parsed and analysed, never rendered by a
  real Jinja engine. Repo scripts are never run.
- **Never trust a size field.** Every length/count/offset is validated against the bytes actually
  remaining before use. Hard caps on everything.
- **Offline by default.** Nothing leaves the machine unless `--online` (or the `repo` command) is used.
- **Low false-positive rate.** Malicious templates are rare (~1 in 5,400 in a 2026 HF-wide scan, all PoCs),
  so unknown ≠ malicious. Known-good template DB + readable diffs over alarms.
- **Data, not code, for vulnerability info.** Vulnerable runner version ranges live in versioned JSON
  sourced from real advisories, updatable without a release.
- **CI friendly.** Exit codes `0` clean, `1` warnings, `2` high/critical, `3` tool error. JSON + SARIF output.

## Tech stack

- C# / .NET 10, Native AOT single-file binaries: win-x64, win-arm64, linux-x64, linux-arm64, osx-arm64.
- `System.CommandLine` for the CLI. No other runtime dependencies in Core.
- xUnit tests; SharpFuzz for parser fuzzing.
- MIT licence.

## Solution layout

```
src/
  ModelSafetyCheck.Core       GGUF parser (strict, span-based, memory-mapped, hard limits)
  ModelSafetyCheck.Jinja      Jinja lexer/parser for analysis only (never renders)
  ModelSafetyCheck.Rules      IRule, Finding, Severity, rule implementations, scan engine
  ModelSafetyCheck.Local      Discovery of installed models (Ollama, LM Studio, llama.cpp cache)
  ModelSafetyCheck.Cli        `modelcheck` executable, output formatters
tests/
  ModelSafetyCheck.Tests      Unit tests + generated malicious fixtures (GgufWriter)
data/
  known-templates.json        Hashes of official chat templates (phase 2)
  runner-vulns.json           Vulnerable runner version ranges (phase 2)
```

## Feature checklist

Status: `[ ]` todo · `[~]` partial · `[x]` done. Every rule has a stable ID.

### Phase 1 — MVP: `scan` + `local`

Core parser
- [x] P-01 Read-only, bounds-checked stream reader (every read checked against bytes remaining; stream-based so the same parser works over HTTP Range for `repo`)
- [x] P-02 Parse header: magic, version (1–3; v1 uses 32-bit counts), tensor count, KV count
- [x] P-03 Parse all KV types incl. nested arrays (with depth limit)
- [x] P-04 Parse tensor infos (name, n_dims, dims, type, offset)
- [x] P-05 Hard limits: string length, array length, KV count, tensor count, nesting depth
- [x] P-06 Parser never throws on hostile input — returns structured parse errors as findings
- [x] P-07 Compute tensor data start (alignment from `general.alignment`, default 32)

Structural rules (GGUF-S)
- [x] S001 Bad magic / unsupported version
- [x] S002 Counts impossible for file size
- [x] S003 String/array length exceeds remaining bytes (parse failure)
- [x] S004 n_dims > 4 or zero dimension
- [x] S005 Element count overflow (product of dims)
- [x] S006 Unknown tensor type
- [x] S007 Tensor offset not aligned
- [x] S008 Tensor data extends beyond end of file (Bleeding Llama class)
- [x] S009 Overlapping tensors
- [x] S010 Duplicate KV keys / duplicate tensor names
- [x] S011 Unexplained gap between tensors (> alignment padding)
- [x] S012 Trailing data after last tensor
- [x] S013 Invalid alignment value (not power of two / zero)

Metadata rules (GGUF-M)
- [x] M001 Oversized string values
- [x] M002 High-entropy / base64-looking blobs
- [x] M003 Executable signatures inside strings or slack space (MZ, ELF, PK, `#!`, Mach-O)
- [x] M004 URLs in metadata (info)
- [x] M005 Invisible / bidi / Unicode tag characters in any string
- [x] M006 Unknown top-level key namespaces (info)

Template rules (GGUF-T) — applied to `tokenizer.chat_template` and every `tokenizer.chat_template.*`
- [x] T001 Template present / extracted (info, with SHA-256)
- [x] T002 Jinja sandbox-escape primitives (`__class__`, `__globals__`, `__subclasses__`, `__builtins__`,
          `__mro__`, `__init__`, `__import__`, `lipsum`, `cycler`, `joiner`, `config`, `self`, `request`, `os`, `popen`, `eval`, `exec`)
- [x] T003 URLs, HTML/script/img/iframe tags, markdown image links in template literals
- [x] T004 Imperative / concealment instruction phrases in literals ("do not tell the user", "always include", "ignore previous", …)
- [x] T005 Content-based triggers: conditions that test message content for literal strings
- [x] T006 Time/date/random based conditions (`strftime_now`, `now`, `random`)
- [x] T007 Invisible Unicode inside the template
- [x] T008 Template lex failure / unusually large template
- [x] T009 Fixed natural-language text the template adds (info, quoted so the user can read what the model is told)
- [x] T011 Resource exhaustion: `**` or numeric literals ≥ 1,000,000 (render-time DoS on every prompt)
- [x] T010 Known-good / unknown template (see D-02)
- [ ] T012 Special-token injection: template emits role markers taken from user content unescaped — phase 2

Tokenizer rules (GGUF-K)
- [x] K001 BOS/EOS/PAD/UNK ids out of vocabulary range
- [x] K002 Vocab size ≠ embedding tensor dimension
- [x] K003 Special/added tokens whose text looks like instructions (see phase 2)

Local discovery (`local`)
- [x] L-01 LM Studio model dirs (`~/.lmstudio/models`, `~/.cache/lm-studio/models`)
- [x] L-02 Ollama store (`OLLAMA_MODELS` or `~/.ollama/models`): read manifests, resolve GGUF blob
- [x] L-03 Ollama **template layer** (`application/vnd.ollama.image.template`) scanned with GGUF-T rules — this is the template that actually runs
- [x] L-04 Ollama system-prompt layer (`application/vnd.ollama.image.system`) scanned with T003/T004/T007
- [x] L-05 O003 Info when the Ollama template layer overrides the GGUF's embedded one (different dialects, so no text diff; both are scanned)
- [x] O001 Malformed layer digest in a manifest (path traversal guard; layer not opened)
- [x] O002 Manifest references a missing blob
- [x] O004 Oversized template/system layer
- [x] L-09 Ollama projector and adapter layers scanned as GGUF too
- [x] L-06 llama.cpp cache (`LLAMA_CACHE`, platform default)
- [x] L-07 Hugging Face hub cache `.gguf` files
- [x] L-08 LM Studio per-model prompt-template overrides (user config under `~/.lmstudio/.internal/`) — these replace the embedded template the same way Ollama's layer does
- [x] L-10 Ollama `renderer`/`parser` built-in formatting noted (O005)

CLI / output
- [x] C-01 `modelcheck scan <path...>` (files or directories, recursive)
- [x] C-02 `modelcheck local`
- [x] C-03 Text output with severity colours
- [x] C-04 `--format json`
- [x] C-05 `--dump-template` prints extracted templates
- [x] C-06 Exit codes 0/1/2/3
- [x] C-07 `--min-severity` filter
- [x] C-08 `--format sarif`
- [x] C-09 Native AOT publish verified on win-x64 (4.8 MB single exe, no trim/AOT warnings). On Windows the link step needs the VS C++ build tools and `vswhere.exe` on PATH (`C:\Program Files (x86)\Microsoft Visual Studio\Installer`)

Testing
- [x] X-01 `GgufWriter` test helper that can write valid and deliberately malformed files
- [x] X-02 One fixture per structural rule
- [x] X-03 Malicious template fixtures (SSTI, trigger, hidden instruction, unicode tags)
- [x] X-04 Clean template fixtures from real model families (no false positives) — ChatML/Qwen, Llama 3, Mistral, Gemma, SmolLM3 mode switches, Ollama Go template; also verified clean on a real Gemma 4 12B GGUF
- [~] X-06 False-positive corpus: official-template benchmark done; top-500 GGUF repo corpus via `repo` still TODO
- [x] X-07 CI matrix workflow written (ubuntu/windows/macos); not run yet
- [~] X-05 Mutation fuzz test done; SharpFuzz harness TODO

### Phase 2 — `audit`, reference data, releases

Reference data (`data/`, embedded; a newer copy in `~/.modelcheck/data` or `$MODELCHECK_DATA` overrides it)
- [x] D-01 `known-templates.json`: 50 templates (41 distinct) from 50 official/established repos — Qwen 2.5/3/Coder/QwQ, DeepSeek R1/V3, Phi 3.5/4, GPT-OSS, Gemma 2/3/3n/4, Llama 3/3.1/3.2/3.3/4, Mistral/Nemo/Small/Devstral, Granite, SmolLM, OLMo, GLM, Kimi K2, LFM2, Nemotron, Command R
- [x] D-02 T010: exact match → Info; ≥85% similar copy with added prose lines → Medium (shows added lines, prose first); larger differences → Info "different version"; no match → Info
- [x] D-03 Whitespace-insensitive normalised hash
- [x] D-04 `tools/TemplateDbBuilder` regenerates the DB from `data/template-sources.json` (HF_TOKEN optional). Version = build date
- [x] D-05 `runner-vulns.json`: CVE-2026-7482 Bleeding Llama (<0.17.1), CVE-2026-42248/42249 Windows updater (0.12.10–<0.23.0, **fix version only third-party reported**, marked `confidence: reported`), Ollama desktop drive-by 2025 (0.10.0, fixed 0.10.1, no CVE), CVE-2024-37032 (<0.1.34), CVE-2024-28224 (<0.1.29), CVE-2024-34359 llama-cpp-python (0.2.30–<0.2.72), CVE-2026-5760 SGLang (<0.5.11, reported). Each entry lists its sources
- [x] D-06 Exact match with an official template downgrades heuristic hits to Info (official templates contain e.g. "do not tell the user about function calls"; injected text breaks the exact match)
- [ ] D-07 Keep historical template versions per repo so stale-but-official templates match exactly
- [ ] D-08 Scheduled CI job that rebuilds the template DB and opens a PR on change

`audit` command
- [x] A-01 Runner detection: Ollama (running server `/api/version`, else CLI), LM Studio (`historical-version-info.json`), llama-cpp-python / SGLang / vLLM (first Python on PATH only; other venvs are not seen)
- [x] A-02 A001 version matching against `runner-vulns.json`, platform-aware, with fix text and sources
- [x] A-03 A002 `OLLAMA_HOST` exposure + A003 `OLLAMA_ORIGINS=*`: process env, Windows user/machine env, systemd units and drop-ins (system + user), `/etc/environment`, `launchctl getenv`
- [x] A-04 A004 non-loopback listeners on 11434/1234/30000 (High) and 8080/8000/5001 (Medium); `lsof` fallback where .NET can't list listeners
- [x] A-05 A005 Docker containers publishing AI ports on 0.0.0.0/:: (ufw bypass note on Linux)
- [~] A-06 LM Studio network/auth settings: LM Studio only writes its server config once configured and the schema is undocumented, so exposure is covered by A004 + the A006 probe instead. TODO: parse the server config once the schema is known
- [x] A-07 A006 `--probe`: unauthenticated request to exposed servers via this machine's own LAN addresses
- [~] A-08 Ollama Windows auto-update: covered by the CVE-2026-42248 entry's remediation (the setting itself is not read)
- [x] A-09 Every network/runner finding includes a "Fix:" line
- [ ] A-10 Identify the process that owns an exposed port (PID → executable)
- [ ] A-11 Read LM Studio `mcp.json` and agent tool configs for tools granting shell/file access (feeds the L5 rating)

Agent risk (`audit --agent-dir <path>`)
- [x] G-01 G001 secrets by file name (.env*, SSH keys, key stores, .netrc, .git-credentials, cloud creds, tfstate) and content (private keys, AWS, GitHub, OpenAI, Anthropic, Slack, Google, Stripe, HF, npm tokens, credentials in URLs incl. `.git/config`). Values are never printed
- [x] G-02 G002 per-layer rating L1–L5 with escalation (exposed + vulnerable runner; exposed + readable secrets)
- [x] G-03 Privilege-separation guidance

Other
- [x] K003 Control/user-defined tokens containing instructions, invisible characters, URLs or sentences (parser keeps `tokenizer.ggml.token_type`)
- [x] L-06 / L-07 llama.cpp and Hugging Face hub caches (symlinks de-duplicated)
- [x] L-08 LM Studio per-model overrides and presets: prompt templates (Jinja) and system prompts scanned
- [x] L-10 O005 Ollama config `renderer`/`parser` noted (formatting code not on disk)
- [x] C-08 `--format sarif` (SARIF 2.1.0 with `security-severity` for GitHub code scanning)
- [~] X-05 Mutation fuzz test in the suite (3 × 3,000 mutated files, fixed seeds). Coverage-guided SharpFuzz harness still TODO
- [~] X-06 False-positive benchmark: every official template in the DB analyses clean; raw heuristics fire on only 2/41 before the official-match downgrade. Top-500 GGUF repo corpus still TODO
- [x] X-07 CI on ubuntu/windows/macos (`.github/workflows/ci.yml`). Not run yet (no remote)
- [x] R-01 `.github/workflows/release.yml`: tag `v*` → Native AOT for win-x64, win-arm64, linux-x64, linux-arm64, osx-arm64 + SHA256SUMS → GitHub release. Not run yet
- [x] R-02 `dotnet pack` → `ModelSafetyCheck` dotnet tool (portable); `dotnet publish -r <rid>` → native single binary. Both verified locally
- [x] R-03 `.gitattributes` normalises line endings

### Phase 3 — `repo` + `watch`

`repo <org/name | URL>...` (`--max-files`, `--all-files`, `--budget-mb`)
- [x] H-01 HF API with `?blobs=true` (files, LFS sha256, tags, cardData, displayed GGUF template). HF_TOKEN is sent only to huggingface.co
- [x] H-02 Executables/scripts (High), Python (Medium), archives (Medium)
- [x] H-03 README lures: run .bat/.ps1/.exe/scripts, pipe-to-shell, encoded PowerShell, disable AV, `trust_remote_code`, hidden characters. High for unknown publishers, Medium for official/quantizers
- [x] H-04 Header-only GGUF scan via `HttpRangeStream` (1 MiB blocks, budget cap). ~16 MiB read for a 7–12 GB Gemma 4 file. Split GGUFs: first shard only. Default 6 files spread across sizes
- [x] H-05 File template vs HF-displayed template (High if the file's template also has warnings, else Medium = likely a stale upload); differing templates across files. Also scans `chat_template.jinja` / `tokenizer_config.json` in non-GGUF repos
- [x] H-06 Lineage from `base_model:*` tags and card; abliterated/merge/uncensored markers
- [x] H-07 Publisher tier from `data/trusted-publishers.json`
- [x] H-08 New repo with >50k downloads; card naming an official org ≥3 times with no base model (impersonation)
- [x] H-09 Pickle formats → picklescan/safetensors advice
- [ ] H-10 `local --online`: match local LM Studio / HF-cache files to their repo by path and verify the LFS sha256
- [ ] H-11 Card-similarity check against the claimed base model's card (copied cards)

`watch` (`--baseline`, `--update`, `--store`, `--log`, `--print-schedule`, `--install-schedule`)
- [x] W-01 Snapshot store `~/.modelcheck/snapshots.json`: target → weights fingerprint (Ollama blob digest / file size+mtime) + sha256 of every template and system prompt
- [x] W-02 First run saves a baseline; later runs report changes; `--update` accepts them
- [x] W-03 W001 High: template/system prompt changed or added with unchanged weights; W001 Medium for LM Studio override changes; W002 Info for model updates; W003 Info for added/removed models
- [x] W-04 Schedule plans: Windows `schtasks` hourly, systemd user timer, launchd agent. `--print-schedule` verified on Windows; `--install-schedule` not run here because it changes the system
- [ ] W-05 Desktop notification on W001

### Phase 4 — later

- [ ] F-01 GitHub Action wrapper
- [ ] F-02 Safe template evaluator (own interpreter over the Jinja AST, no host access) for `--explain`: render with sample conversations and show exactly what the model sees, with/without candidate triggers
- [ ] F-03 Optional ONNX prompt-injection classifier on extracted literals
- [ ] F-04 Integrations: Open WebUI / LM Studio plugin, pre-pull hook for Ollama
- [ ] F-05 safetensors / ONNX / other formats header checks
- [ ] F-06 Docs site: the five-layer model, hardening guide

## Sources to verify against (not the video transcript)

- Checkmarx — "Llama Drama", CVE-2024-34359 (llama-cpp-python SSTI)
- Databricks — GGML/GGUF heap overflow advisories (2024)
- Pillar Security — poisoned GGUF chat templates
- Cyera — "Bleeding Llama" (Ollama tensor size trust)
- Wiz — Ollama path traversal (2024)
- SentinelOne / Censys — exposed Ollama servers study (Jan 2026)
- ProjectDiscovery — tool-calling backdoor fine-tune
- Anthropic — Sleeper Agents (2024); Anthropic + UK AISI — 250-document poisoning
- HiddenLayer — fake "Privacy Filter" repo
