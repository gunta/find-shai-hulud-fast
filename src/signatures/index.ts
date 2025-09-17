import fs from "node:fs/promises";
import path from "node:path";

export type Indicator =
  | { type: "string"; value: string }
  | { type: "regex"; value: string }
  | { type: "glob"; pattern: string }
  | { type: "sha256"; value: string }
  | { type: "package"; name: string; version: string };

export interface Signature {
  id: string;
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  indicators: Indicator[];
}

export interface SignaturePack {
  version: number;
  updated: string;
  signatures: Signature[];
}

interface CompromisedPackageEntry {
  name: string;
  version: string;
}

interface CompromisedPackageFile {
  updated: string;
  source?: string;
  packages: CompromisedPackageEntry[];
}

export interface LoadedSignature extends Signature {
  regexes: RegExp[];
  strings: string[];
  globs: string[];
  hashes: string[];
  packages: Extract<Indicator, { type: "package" }>[];
}

async function loadPack(filePath: string): Promise<SignaturePack> {
  const content = await fs.readFile(filePath, "utf8");
  return JSON.parse(content) as SignaturePack;
}

async function loadCompromisedPackages(baseDir: string): Promise<CompromisedPackageEntry[]> {
  const filePath = path.resolve(baseDir, "compromised-packages.json");
  try {
    const content = await fs.readFile(filePath, "utf8");
    const parsed = JSON.parse(content) as CompromisedPackageFile;
    if (!Array.isArray(parsed.packages)) {
      throw new Error("Invalid compromised packages file: missing packages array");
    }
    const seen = new Set<string>();
    const result: CompromisedPackageEntry[] = [];
    for (const entry of parsed.packages) {
      if (!entry || typeof entry !== "object") continue;
      const { name, version } = entry;
      if (typeof name !== "string" || typeof version !== "string") continue;
      const key = `${name}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      result.push({ name, version });
    }
    return result;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return [];
    }
    throw error;
  }
}

export interface LoadedSignaturePack {
  sourcePath: string;
  signatures: LoadedSignature[];
}

export async function loadSignatures(customPath?: string): Promise<LoadedSignaturePack> {
  const root = customPath
    ? path.resolve(customPath)
    : path.resolve(import.meta.dir, "./shai-hulud.json");
  const pack = await loadPack(root);
  const baseDir = path.dirname(root);
  const compromisedPackages = await loadCompromisedPackages(baseDir);
  if (compromisedPackages.length) {
    const lockfileGlobs = [
      "**/package-lock.json",
      "**/npm-shrinkwrap.json",
      "**/pnpm-lock.yaml",
      "**/pnpm-lock.yml",
      "**/yarn.lock",
      "**/bun.lock",
      "**/bun.lockb",
    ];
    pack.signatures.push({
      id: "shai-hulud:compromised-packages",
      title: "Known compromised npm packages (JFrog 2025-09-16)",
      severity: "critical",
      description:
        "Detects dependencies on npm packages compromised in the September 2025 shai hulud supply-chain attack (JFrog Security Research).",
      indicators: [
        ...lockfileGlobs.map((pattern) => ({ type: "glob" as const, pattern })),
        ...compromisedPackages.map((entry) => ({
          type: "package" as const,
          name: entry.name,
          version: entry.version,
        })),
      ],
    });
  }
  const signatures = pack.signatures.map((sig) => ({
    ...sig,
    regexes: sig.indicators
      .filter((ind): ind is Extract<Indicator, { type: "regex" }> => ind.type === "regex")
      .map((ind) => new RegExp(ind.value, "i")),
    strings: sig.indicators
      .filter((ind): ind is Extract<Indicator, { type: "string" }> => ind.type === "string")
      .map((ind) => ind.value.toLowerCase()),
    globs: sig.indicators
      .filter((ind): ind is Extract<Indicator, { type: "glob" }> => ind.type === "glob")
      .map((ind) => ind.pattern),
    hashes: sig.indicators
      .filter((ind): ind is Extract<Indicator, { type: "sha256" }> => ind.type === "sha256")
      .map((ind) => ind.value.toLowerCase()),
    packages: sig.indicators.filter(
      (ind): ind is Extract<Indicator, { type: "package" }> => ind.type === "package"
    ),
  }));

  return { sourcePath: root, signatures };
}
