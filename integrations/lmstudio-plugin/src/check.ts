// Runs the modelcheck executable on a model file and summarises the result. No LM Studio dependency, so it can
// be tested with plain Node (`npm test`).
import { execFile } from "node:child_process";
import { statSync } from "node:fs";

export const SEVERITIES = ["Info", "Low", "Medium", "High", "Critical"];

export interface Finding {
  ruleId: string;
  severity: string;
  title: string;
  detail: string;
  location?: string;
}

export interface Verdict {
  findings: Finding[];
  worst: string;
  error?: string;
}

const cache = new Map<string, Verdict>();

/** True when `severity` is at or above `threshold`. */
export function atLeast(severity: string, threshold: string): boolean {
  return SEVERITIES.indexOf(severity) >= SEVERITIES.indexOf(threshold);
}

/** The most serious findings, for a one-line status. */
export function summarize(verdict: Verdict): string {
  return verdict.findings
    .filter(f => atLeast(f.severity, "Medium"))
    .sort((a, b) => SEVERITIES.indexOf(b.severity) - SEVERITIES.indexOf(a.severity))
    .slice(0, 3)
    .map(f => `${f.ruleId} ${f.severity}: ${f.title}`)
    .join("; ");
}

/**
 * Scans a model file with `modelcheck scan <file> --format json`. Results are cached per file, size and
 * modification time, so a re-downloaded or edited file is checked again.
 */
export function scan(modelcheck: string, file: string, timeoutMs = 120_000): Promise<Verdict> {
  let key: string;
  try {
    const info = statSync(file);
    key = `${file}|${info.size}|${info.mtimeMs}`;
  } catch {
    return Promise.resolve({ findings: [], worst: "Info", error: `model file not found: ${file}` });
  }
  const hit = cache.get(key);
  if (hit) return Promise.resolve(hit);

  return new Promise(resolve => {
    execFile(modelcheck, ["scan", file, "--format", "json"], { timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024, windowsHide: true }, (error, stdout, stderr) => {
      // Exit codes 1 and 2 are results (warnings / high findings); 3 is a scan error; no numeric code means it did not run.
      const raw = (error as { code?: unknown } | null)?.code;
      const code = error === null ? 0 : typeof raw === "number" ? raw : -1;
      if (code === -1 || code === 3 || !stdout.trim()) {
        const reason = code === -1 ? `could not run ${modelcheck}: ${error?.message}` : stderr.trim() || `modelcheck exited with ${code}`;
        resolve({ findings: [], worst: "Info", error: reason });
        return;
      }
      try {
        const reports = JSON.parse(stdout) as Array<{ findings?: Finding[]; error?: string }>;
        const failed = reports.find(r => r.error);
        if (failed) {
          resolve({ findings: [], worst: "Info", error: failed.error });
          return;
        }
        const findings = reports.flatMap(r => r.findings ?? []);
        const worst = findings.reduce((w, f) => (atLeast(f.severity, w) ? f.severity : w), "Info");
        const verdict = { findings, worst };
        cache.set(key, verdict);
        resolve(verdict);
      } catch (e) {
        resolve({ findings: [], worst: "Info", error: `unreadable modelcheck output: ${(e as Error).message}` });
      }
    });
  });
}
