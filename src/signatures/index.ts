import fs from "node:fs/promises";
import path from "node:path";

export type Indicator =
  | { type: "string"; value: string }
  | { type: "regex"; value: string }
  | { type: "glob"; pattern: string }
  | { type: "sha256"; value: string }
  | { type: "heuristic"; value: "long-line" };

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

export interface LoadedSignature extends Signature {
  regexes: RegExp[];
  strings: string[];
  globs: string[];
  hashes: string[];
  heuristics: Indicator[];
}

async function loadPack(filePath: string): Promise<SignaturePack> {
  const content = await fs.readFile(filePath, "utf8");
  return JSON.parse(content) as SignaturePack;
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
    heuristics: sig.indicators.filter((ind) => ind.type === "heuristic"),
  }));

  return { sourcePath: root, signatures };
}
