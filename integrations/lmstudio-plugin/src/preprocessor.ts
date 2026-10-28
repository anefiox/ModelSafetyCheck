import { type ChatMessage, type PromptPreprocessorController } from "@lmstudio/sdk";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import { atLeast, scan, summarize } from "./check";
import { globalConfigSchematics } from "./config";

/**
 * Before each message is sent, checks the loaded model's GGUF file with modelcheck (structure, metadata and the
 * embedded chat template, including rendered trigger probes). Blocks the message when findings reach the
 * configured severity. Results are cached per file, so only the first message with a model pays for the scan.
 */
export async function preprocess(ctl: PromptPreprocessorController, userMessage: ChatMessage) {
  const config = ctl.getGlobalPluginConfig(globalConfigSchematics);
  const source = await ctl.tokenSource();
  if (!("getModelInfo" in source)) return userMessage; // a generator plugin, not a model file
  const info = await source.getModelInfo();
  if (!info || info.format !== "gguf") return userMessage;

  const modelsDirectory = config.get("modelsDirectory") || join(homedir(), ".lmstudio", "models");
  const file = isAbsolute(info.path) ? info.path : join(modelsDirectory, info.path);
  const status = ctl.createStatus({ status: "loading", text: `modelcheck: checking ${info.modelKey}` });
  const verdict = await scan(config.get("modelcheckPath"), file);

  if (verdict.error) {
    status.setState({ status: "error", text: `modelcheck could not check ${info.modelKey}: ${verdict.error}` });
    if (config.get("failClosed")) throw new Error(`modelcheck could not check ${info.modelKey}: ${verdict.error}`);
    return userMessage;
  }

  const summary = summarize(verdict);
  if (atLeast(verdict.worst, config.get("blockAt"))) {
    status.setState({ status: "error", text: `modelcheck: ${summary}` });
    if (config.get("block"))
      throw new Error(`Blocked by modelcheck: ${info.modelKey} has ${summary}. Run modelcheck explain on ${file} for details.`);
    return userMessage;
  }

  status.setState({ status: "done", text: `modelcheck: ${info.modelKey}: ${summary || "no findings"}` });
  return userMessage;
}
