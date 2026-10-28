# LM Studio plugin: modelcheck-guard

A prompt-preprocessor plugin for LM Studio's plugin SDK (beta). Before each message is sent, it runs
`modelcheck scan` on the loaded model's GGUF file — structure, metadata and the embedded chat template, including
the rendered trigger probes — and blocks the message when findings reach the configured severity (High by default).
Results are cached per file, so only the first message with a model waits for the scan (a few seconds).

The plugin declares `sandbox.enabled: false` in `manifest.json` because it runs the local `modelcheck` executable
and reads the model file; LM Studio shows that reason when you install it.

## Use it

1. Install `modelcheck` (a release binary) and note its path.
2. In this folder: `npm install`, then `lms dev` (keep it running; LM Studio must be open). The plugin appears in
   LM Studio's plugin list.
3. In the plugin's settings set **modelcheck executable** to the binary's path (or leave `modelcheck` if it is on
   PATH), and choose **Block chats at**. Turn **Block flagged models** off to only show a warning status.

To share it: `lms push` (uploads to LM Studio Hub under the `owner` in `manifest.json`).

## Limits

- It checks the GGUF file. A prompt template you override in LM Studio's model settings is not in the file;
  `modelcheck local` checks those overrides.
- The plugin SDK is in beta and blocking is done by throwing from the preprocessor, which LM Studio reports as an
  error for that message. Tested here: typecheck against `@lmstudio/sdk` 2.1.0 and the modelcheck wrapper against
  the real binary (`npm test`). Not yet exercised inside a running LM Studio.

## Develop

```bash
npm install
npm run typecheck
MODELCHECK=path/to/modelcheck npm test
```
