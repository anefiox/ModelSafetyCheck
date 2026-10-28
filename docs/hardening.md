# Hardening a local AI setup

A local model setup has five layers, and each needs its own defence. Most people only think about the first.
None of this takes more than an afternoon. `modelcheck audit` checks layers 1–5 in one go.

## 1. The model file

- Get weights from the lab itself or an established quantizer. `modelcheck repo <org/name>` (or `ollama:<model>`)
  shows the publisher, lineage and any scripts in the repo before you download.
- Prefer GGUF or safetensors. Pickle files (`.bin`, `.pt`, `.ckpt`) run code when loaded; `modelcheck scan`
  lists every import they make.
- A matching SHA-256 only proves you got the file the uploader meant to give you. It says nothing about the uploader.
- Never run scripts from a model repo. A model card that asks you to is a red flag (rule H003).

## 2. The chat template

- The template is code that runs on every prompt. Read it: `modelcheck explain model.gguf` prints exactly
  what the model receives, and what changes when trigger phrases or dates are present.
- Ollama and LM Studio can replace the template that is inside the file. `modelcheck local` scans what actually runs.
- Run `modelcheck watch --install-schedule` to be told when a template changes without a model update.

## 3. The runner

- Keep Ollama, LM Studio, llama.cpp, vLLM and SGLang updated. `modelcheck audit` compares installed versions with
  known vulnerabilities, including Bleeding Llama (Ollama < 0.17.1) and template-injection bugs (llama-cpp-python
  < 0.2.72, SGLang < 0.5.11).
- On Windows, until you have confirmed your Ollama version includes the updater fix (CVE-2026-42248/42249), turn off auto-update.

## 4. The port

- Leave servers on `127.0.0.1`. Do not set `OLLAMA_HOST=0.0.0.0` or `OLLAMA_ORIGINS=*`.
- To use the model from another device, use an encrypted tunnel (for example Tailscale) or a reverse proxy that requires authentication. In LM Studio, turn on "require authentication".
- Publish Docker ports on loopback only (`-p 127.0.0.1:11434:11434`): Docker's own firewall rules bypass ufw.
- `modelcheck audit --probe` tests whether a server answers your LAN without credentials.

## 5. Weights plus tools

Backdoored weights cannot be detected by scanning. What you control is what a compromised model can reach.

- Give tools only to models with official weights. Treat an abliterated or merged model from an unknown account like a pull request from a stranger.
- Keep secrets out of the agent's working directory: no `.env`, SSH keys or cloud credentials (`modelcheck audit --agent-dir <dir>`).
- Do not give one agent both a file/shell tool and a network tool. Split them, and log what passes between them (rule G004).
- Do not point file tools at your whole home directory.
- Treat text an agent reads (web pages, files, emails) as untrusted. Templates insert it verbatim, so a page containing
  a model's own control tokens (for example `<|im_start|>system`) can look like a real system turn to some runners.
  This depends on the runner's tokenizer, not the template, so no scanner can rule it out; limit what the agent can do instead.
