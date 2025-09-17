import type { LoadedSignature } from "../signatures/index";
import { matchGlob } from "../utils/glob";
import { sha256File } from "../utils/hash";

interface InitMessage {
  type: "init";
  signatures: LoadedSignature[];
  maxBytes: number;
}

interface ScanMessage {
  type: "scan";
  path: string;
  size: number;
}

interface ShutdownMessage {
  type: "shutdown";
}

interface MatchResult {
  signatureId: string;
  title: string;
  severity: string;
  description: string;
  indicatorType: string;
  indicatorValue: string;
}

interface ScanResultMessage {
  type: "result";
  path: string;
  bytesRead: number;
  matches: MatchResult[];
  error?: string;
}

type IncomingMessage = InitMessage | ScanMessage | ShutdownMessage;

declare const self: Worker;

let signatures: LoadedSignature[] = [];
let maxBytes = 5 * 1024 * 1024;
let packageIndex = new Map<string, Map<string, LoadedSignature[]>>();
let packageTokens: Array<{
  token: string;
  name: string;
  version: string;
  signatures: LoadedSignature[];
}> = [];
const textDecoder = new TextDecoder();
const textEncoder = new TextEncoder();

function concatChunks(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const chunk of chunks) {
    total += chunk.byteLength;
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

function rebuildPackageIndex(newSignatures: LoadedSignature[]) {
  packageIndex = new Map();
  for (const signature of newSignatures) {
    if (!signature.packages?.length) continue;
    for (const pkg of signature.packages) {
      const name = pkg.name;
      const version = pkg.version;
      if (!name || !version) continue;
      let versionMap = packageIndex.get(name);
      if (!versionMap) {
        versionMap = new Map();
        packageIndex.set(name, versionMap);
      }
      let sigs = versionMap.get(version);
      if (!sigs) {
        sigs = [];
        versionMap.set(version, sigs);
      }
      if (!sigs.includes(signature)) {
        sigs.push(signature);
      }
    }
  }
  packageTokens = [];
  for (const [name, versions] of packageIndex) {
    for (const [version, sigs] of versions) {
      packageTokens.push({ token: `${name}@${version}`, name, version, signatures: sigs });
    }
  }
}

function shouldForceFullRead(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return (
    lower.endsWith("package-lock.json") ||
    lower.endsWith("npm-shrinkwrap.json") ||
    lower.endsWith("yarn.lock") ||
    lower.endsWith("pnpm-lock.yaml") ||
    lower.endsWith("pnpm-lock.yml") ||
    lower.endsWith("bun.lock") ||
    lower.endsWith("bun.lockb")
  );
}

function extractPackageNameFromKey(key: string, value: unknown): string | null {
  if (!key) {
    if (value && typeof value === "object" && "name" in (value as Record<string, unknown>)) {
      const name = (value as Record<string, unknown>).name;
      return typeof name === "string" ? name : null;
    }
    return null;
  }
  if (value && typeof value === "object" && "name" in (value as Record<string, unknown>)) {
    const name = (value as Record<string, unknown>).name;
    if (typeof name === "string") return name;
  }
  const parts = key.split("node_modules/");
  const candidate = parts[parts.length - 1];
  return candidate || null;
}

function recordPackageMatch(
  matches: MatchResult[],
  seen: Map<string, Set<string>>,
  name: string,
  version: string
) {
  const versionMap = packageIndex.get(name);
  if (!versionMap) return;
  const signaturesForVersion = versionMap.get(version);
  if (!signaturesForVersion) return;
  const indicatorValue = `${name}@${version}`;
  for (const signature of signaturesForVersion) {
    let seenValues = seen.get(signature.id);
    if (!seenValues) {
      seenValues = new Set();
      seen.set(signature.id, seenValues);
    }
    if (seenValues.has(indicatorValue)) continue;
    seenValues.add(indicatorValue);
    matches.push({
      signatureId: signature.id,
      title: signature.title,
      severity: signature.severity,
      description: signature.description,
      indicatorType: "package",
      indicatorValue,
    });
  }
}

function walkLockDependencies(
  matches: MatchResult[],
  seen: Map<string, Set<string>>,
  deps: Record<string, unknown>
) {
  for (const [depName, value] of Object.entries(deps)) {
    if (typeof depName !== "string") continue;
    if (typeof value === "string") {
      recordPackageMatch(matches, seen, depName, value);
      continue;
    }
    if (!value || typeof value !== "object") continue;
    const record = value as Record<string, unknown>;
    const version = record.version;
    if (typeof version === "string") {
      recordPackageMatch(matches, seen, depName, version);
    }
    if (record.dependencies && typeof record.dependencies === "object") {
      walkLockDependencies(matches, seen, record.dependencies as Record<string, unknown>);
    }
  }
}

function scanPackageLock(
  matches: MatchResult[],
  seen: Map<string, Set<string>>,
  content: string
) {
  let data: unknown;
  try {
    data = JSON.parse(content);
  } catch (error) {
    return;
  }
  if (!data || typeof data !== "object") return;
  const obj = data as Record<string, unknown>;

  const packages = obj.packages;
  if (packages && typeof packages === "object") {
    for (const [key, value] of Object.entries(packages as Record<string, unknown>)) {
      if (!value || typeof value !== "object") continue;
      const version = (value as Record<string, unknown>).version;
      if (typeof version !== "string") continue;
      const name = extractPackageNameFromKey(key, value);
      if (!name) continue;
      recordPackageMatch(matches, seen, name, version);
    }
  }

  const dependencies = obj.dependencies;
  if (dependencies && typeof dependencies === "object") {
    walkLockDependencies(matches, seen, dependencies as Record<string, unknown>);
  }
}

function detectCompromisedPackages(
  filePath: string,
  content: string
): MatchResult[] {
  if (!packageTokens.length) return [];
  const matches: MatchResult[] = [];
  const seen = new Map<string, Set<string>>();
  const lowerPath = filePath.toLowerCase();

  if (lowerPath.endsWith("package-lock.json") || lowerPath.endsWith("npm-shrinkwrap.json")) {
    scanPackageLock(matches, seen, content);
    return matches;
  }

  const checkTokens = () => {
    for (const entry of packageTokens) {
      if (content.includes(entry.token)) {
        recordPackageMatch(matches, seen, entry.name, entry.version);
      }
    }
  };

  if (
    lowerPath.endsWith("pnpm-lock.yaml") ||
    lowerPath.endsWith("pnpm-lock.yml") ||
    lowerPath.endsWith("yarn.lock") ||
    lowerPath.endsWith("bun.lock") ||
    lowerPath.endsWith("bun.lockb")
  ) {
    checkTokens();
  }

  return matches;
}

self.onmessage = async (event: MessageEvent<IncomingMessage>) => {
  const message = event.data;
  switch (message.type) {
    case "init":
      signatures = message.signatures;
      maxBytes = message.maxBytes;
      rebuildPackageIndex(signatures);
      break;
    case "scan":
      self.postMessage(await handleScan(message));
      break;
    case "shutdown":
      (self as unknown as { close?: () => void }).close?.();
      break;
  }
};

async function handleScan(message: ScanMessage): Promise<ScanResultMessage> {
  const { path, size } = message;
  const file = Bun.file(path);
  try {
    if (!(await file.exists())) {
      return { type: "result", path, bytesRead: 0, matches: [], error: "missing" };
    }

    const matches: MatchResult[] = [];
    const globMatches = new Map<string, string | null>();
    const relevantSignatures: LoadedSignature[] = [];
    let needsContent = false;

    for (const signature of signatures) {
      let matchedGlob: string | null = null;
      if (signature.globs.length) {
        matchedGlob = signature.globs.find((glob) => matchGlob(path, glob)) ?? null;
        if (!matchedGlob) {
          continue;
        }
      }
      relevantSignatures.push(signature);
      globMatches.set(signature.id, matchedGlob);
      if (!needsContent && (signature.strings.length || signature.regexes.length || signature.packages.length)) {
        needsContent = true;
      }
    }

    if (!relevantSignatures.length) {
      return { type: "result", path, bytesRead: 0, matches };
    }

    for (const signature of relevantSignatures) {
      const matchedGlob = globMatches.get(signature.id);
      const isGlobOnly =
        signature.globs.length > 0 &&
        signature.strings.length === 0 &&
        signature.regexes.length === 0 &&
        signature.hashes.length === 0 &&
        signature.packages.length === 0;
      if (isGlobOnly && matchedGlob) {
        matches.push({
          signatureId: signature.id,
          title: signature.title,
          severity: signature.severity,
          description: signature.description,
          indicatorType: "glob",
          indicatorValue: matchedGlob,
        });
      }
    }

    let bytesRead = 0;
    let content: string | null = null;
    let lower: string | null = null;

    const forceFullRead = needsContent && shouldForceFullRead(path);

    if (needsContent) {
      if (!forceFullRead && size > maxBytes) {
        // Read only the first chunk up to maxBytes to avoid huge memory usage.
        const stream = file.stream();
        const reader = stream.getReader();
        const chunks: Uint8Array[] = [];
        let accumulated = 0;
        while (accumulated < maxBytes) {
          const { done, value } = await reader.read();
          if (done || !value) break;
          chunks.push(value as Uint8Array);
          accumulated += value.length;
        }
        const buffer = concatChunks(chunks);
        content = textDecoder.decode(buffer);
        bytesRead = buffer.byteLength;
      } else {
        content = await file.text();
        bytesRead = textEncoder.encode(content).byteLength;
      }
      lower = content.toLowerCase();
    }

    let digest: string | null = null;
    const ensureDigest = async () => {
      if (digest) return digest;
      digest = await sha256File(path);
      return digest;
    };

    if (content) {
      for (const signature of relevantSignatures) {
        let matched = matches.some((match) => match.signatureId === signature.id);
        if (matched) continue;
        if (signature.globs.length && !globMatches.has(signature.id)) {
          continue;
        }
        if (signature.strings.length && lower) {
          const indicator = signature.strings.find((needle) => lower!.includes(needle));
          if (indicator) {
            matches.push({
              signatureId: signature.id,
              title: signature.title,
              severity: signature.severity,
              description: signature.description,
              indicatorType: "string",
              indicatorValue: indicator,
            });
            continue;
          }
        }

        if (signature.regexes.length && content) {
          const indicator = signature.regexes.find((regex) => regex.test(content!));
          if (indicator) {
            matches.push({
              signatureId: signature.id,
              title: signature.title,
              severity: signature.severity,
              description: signature.description,
              indicatorType: "regex",
              indicatorValue: indicator.source,
            });
            continue;
          }
        }

        if (signature.hashes.length) {
          const hash = await ensureDigest();
          const indicator = signature.hashes.find((h) => h === hash);
          if (indicator) {
            matches.push({
              signatureId: signature.id,
              title: signature.title,
              severity: signature.severity,
              description: signature.description,
              indicatorType: "sha256",
              indicatorValue: indicator,
            });
            continue;
          }
        }
      }

      const packageMatches = detectCompromisedPackages(path, content);
      for (const match of packageMatches) {
        const alreadyExists = matches.some(
          (existing) =>
            existing.signatureId === match.signatureId &&
            existing.indicatorType === match.indicatorType &&
            existing.indicatorValue === match.indicatorValue
        );
        if (!alreadyExists) {
          matches.push(match);
        }
      }
    } else if (relevantSignatures.some((sig) => sig.hashes.length)) {
      const hash = await ensureDigest();
      for (const signature of relevantSignatures) {
        if (signature.globs.length && !globMatches.has(signature.id)) {
          continue;
        }
        if (signature.hashes.includes(hash)) {
          matches.push({
            signatureId: signature.id,
            title: signature.title,
            severity: signature.severity,
            description: signature.description,
            indicatorType: "sha256",
            indicatorValue: hash,
          });
        }
      }
    }

    return { type: "result", path, bytesRead, matches };
  } catch (error) {
    return {
      type: "result",
      path,
      bytesRead: 0,
      matches: [],
      error: error instanceof Error ? error.message : String(error),
    };
  }
}
