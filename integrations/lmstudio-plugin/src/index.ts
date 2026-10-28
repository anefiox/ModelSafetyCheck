import { type PluginContext } from "@lmstudio/sdk";
import { globalConfigSchematics } from "./config";
import { preprocess } from "./preprocessor";

// Plugin entry point: LM Studio calls main() when the plugin loads.
export async function main(context: PluginContext) {
  context.withGlobalConfigSchematics(globalConfigSchematics);
  context.withPromptPreprocessor(preprocess);
}
