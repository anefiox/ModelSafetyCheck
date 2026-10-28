import { createConfigSchematics } from "@lmstudio/sdk";

/** Global (app-wide) settings, shown in LM Studio's plugin settings. */
export const globalConfigSchematics = createConfigSchematics()
  .field("modelcheckPath", "string", { displayName: "modelcheck executable", hint: "Full path, or just modelcheck if it is on PATH." }, "modelcheck")
  .field("modelsDirectory", "string", { displayName: "LM Studio models folder", hint: "Leave empty for ~/.lmstudio/models." }, "")
  .field(
    "blockAt",
    "select",
    {
      displayName: "Block chats at",
      options: [
        { value: "Medium", displayName: "Medium or above" },
        { value: "High", displayName: "High or above" },
        { value: "Critical", displayName: "Critical only" },
      ],
    },
    "High",
  )
  .field("block", "boolean", { displayName: "Block flagged models", hint: "Off: only show a warning in the chat." }, true)
  .field("failClosed", "boolean", { displayName: "Block when the check fails", hint: "For example when modelcheck is not installed." }, false)
  .build();
