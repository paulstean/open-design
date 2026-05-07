import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";

import { redactJsonText, redactText, type RedactionOptions } from "./redaction.js";

export type LogSourceKind = "json" | "text";

export interface LogSource {
  /** Relative path inside the export zip (forward-slash). */
  name: string;
  /** Absolute path on disk to read from. */
  absolutePath: string;
  /** Whether the file should be parsed/redacted as JSON or plain text. */
  kind: LogSourceKind;
  /** Optional max bytes to read from the file tail; omit for whole file. */
  tailBytes?: number;
}

export interface CollectedFile {
  name: string;
  absolutePath: string;
  /** Redacted contents to put into the zip. Null when the file could not be read. */
  content: string | null;
  bytes: number;
  /** Reason the file is missing or unreadable. */
  error?: string;
}

async function readMaybeTail(absolutePath: string, tailBytes: number | undefined): Promise<{ text: string; bytes: number }> {
  if (tailBytes == null || tailBytes <= 0) {
    const buf = await readFile(absolutePath);
    return { text: buf.toString("utf8"), bytes: buf.byteLength };
  }
  const info = await stat(absolutePath);
  const start = Math.max(0, info.size - tailBytes);
  const buf = await readFile(absolutePath);
  const sliced = buf.subarray(start);
  return { text: sliced.toString("utf8"), bytes: sliced.byteLength };
}

export async function collectLogSource(source: LogSource, opts: RedactionOptions = {}): Promise<CollectedFile> {
  try {
    const { text, bytes } = await readMaybeTail(source.absolutePath, source.tailBytes);
    const redacted = source.kind === "json" ? redactJsonText(text, opts) : redactText(text, opts);
    return { name: source.name, absolutePath: source.absolutePath, content: redacted, bytes };
  } catch (error) {
    return {
      name: source.name,
      absolutePath: source.absolutePath,
      content: null,
      bytes: 0,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export async function collectLogSources(sources: LogSource[], opts: RedactionOptions = {}): Promise<CollectedFile[]> {
  return await Promise.all(sources.map((source) => collectLogSource(source, opts)));
}

const DEFAULT_CRASH_DIRS_DARWIN = [
  "/Library/Logs/DiagnosticReports",
];

export interface CrashReportLookup {
  /** Filenames must contain at least one of these substrings (case-insensitive). */
  matchSubstrings: string[];
  /** Only include files modified within this many days. */
  withinDays?: number;
  /** Limit how many reports to include. */
  maxReports?: number;
  /** Override base directories to scan. */
  searchDirs?: string[];
  /** Home directory to derive ~/Library/Logs/DiagnosticReports from. */
  homeDir?: string;
}

export async function findMacOSCrashReports(lookup: CrashReportLookup): Promise<LogSource[]> {
  if (process.platform !== "darwin") return [];
  const within = (lookup.withinDays ?? 7) * 24 * 60 * 60 * 1000;
  const cutoff = Date.now() - within;
  const max = lookup.maxReports ?? 20;
  const dirs = lookup.searchDirs ?? [
    ...(lookup.homeDir ? [join(lookup.homeDir, "Library/Logs/DiagnosticReports")] : []),
    ...DEFAULT_CRASH_DIRS_DARWIN,
  ];
  const matches = lookup.matchSubstrings.map((entry) => entry.toLowerCase());

  const found: { absolutePath: string; mtimeMs: number; name: string }[] = [];
  for (const dir of dirs) {
    let entries: string[];
    try {
      entries = await readdir(dir);
    } catch {
      continue;
    }
    for (const entry of entries) {
      const lower = entry.toLowerCase();
      if (!matches.some((needle) => lower.includes(needle))) continue;
      const absolutePath = join(dir, entry);
      try {
        const info = await stat(absolutePath);
        if (!info.isFile()) continue;
        if (info.mtimeMs < cutoff) continue;
        found.push({ absolutePath, mtimeMs: info.mtimeMs, name: entry });
      } catch {
        continue;
      }
    }
  }

  found.sort((a, b) => b.mtimeMs - a.mtimeMs);
  return found.slice(0, max).map(({ absolutePath, name }) => ({
    name: `crash-reports/${name}`,
    absolutePath,
    kind: "text",
  }));
}
