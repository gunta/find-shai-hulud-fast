import fs from "node:fs/promises";
import path from "node:path";
import { getProfile, getDefaultProfile, listProfiles } from "./registry";

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

export interface SignaturePackManifest {
  id?: string;
  title?: string;
  summary?: string;
  version: number;
  updated: string;
  sources?: string[];
  extends?: string[];
  compromisedPackagesFile?: string;
  compromisedPackages?: CompromisedPackageEntry[];
  compromisedPackagesSignature?: CompromisedPackageSignature;
  signatures: Signature[];
}

interface CompromisedPackageSignature {
  id: string;
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  globs?: string[];
}

export interface SignaturePackSummary {
  profileId?: string;
  manifestId?: string;
  title?: string;
  summary?: string;
  updated?: string;
  sources: string[];
  resolvedProfiles: string[];
}

interface ManifestRecord {
  manifest: SignaturePackManifest;
  absolutePath: string;
}

interface ManifestLoadResult {
  signatures: Signature[];
  records: ManifestRecord[];
  sourcePaths: string[];
  resolvedProfiles: string[];
}

export interface CompromisedPackageEntry {
  name: string;
  version: string;
}

interface LoadContext {
  visited: Set<string>;
}

export interface LoadedSignature extends Signature {
  regexes: RegExp[];
  strings: string[];
  globs: string[];
  hashes: string[];
  packages: Extract<Indicator, { type: "package" }>[];
}

export interface LoadedSignaturePack {
  sourcePaths: string[];
  signatures: LoadedSignature[];
  summary: SignaturePackSummary;
}

export interface LoadSignaturesOptions {
  profileId?: string;
  signatureFile?: string;
}

const DEFAULT_LOCKFILE_GLOBS = [
  "**/package-lock.json",
  "**/npm-shrinkwrap.json",
  "**/pnpm-lock.yaml",
  "**/pnpm-lock.yml",
  "**/yarn.lock",
  "**/bun.lock",
  "**/bun.lockb",
];

function dedupeByKey<T>(items: T[], keyFn: (item: T) => string): T[] {
  const map = new Map<string, T>();
  for (const item of items) {
    map.set(keyFn(item), item);
  }
  return Array.from(map.values());
}

async function readManifest(manifestPath: string): Promise<SignaturePackManifest> {
  const content = await fs.readFile(manifestPath, "utf8");
  return JSON.parse(content) as SignaturePackManifest;
}

async function loadCompromisedPackages(
  manifest: SignaturePackManifest,
  manifestPath: string
): Promise<{ entries: CompromisedPackageEntry[]; sourceFiles: string[] }> {
  const entries: CompromisedPackageEntry[] = [];
  const sourceFiles: string[] = [];
  const manifestDir = path.dirname(manifestPath);
  if (manifest.compromisedPackagesFile) {
    const filePath = path.resolve(manifestDir, manifest.compromisedPackagesFile);
    const content = await fs.readFile(filePath, "utf8");
    sourceFiles.push(filePath);
    const parsed = JSON.parse(content) as {
      packages?: CompromisedPackageEntry[];
    };
    if (Array.isArray(parsed.packages)) {
      for (const pkg of parsed.packages) {
        if (pkg && typeof pkg.name === "string" && typeof pkg.version === "string") {
          entries.push({ name: pkg.name, version: pkg.version });
        }
      }
    }
  }
  if (Array.isArray(manifest.compromisedPackages)) {
    for (const pkg of manifest.compromisedPackages) {
      if (pkg && typeof pkg.name === "string" && typeof pkg.version === "string") {
        entries.push({ name: pkg.name, version: pkg.version });
      }
    }
  }
  return {
    entries: dedupeByKey(entries, (entry) => `${entry.name}@${entry.version}`),
    sourceFiles,
  };
}

function defaultPackageSignature(
  manifest: SignaturePackManifest,
  manifestPath: string
): CompromisedPackageSignature {
  const manifestId = manifest.id ?? path.basename(manifestPath, path.extname(manifestPath));
  return {
    id: `${manifestId}:compromised-packages`,
    title: `Known compromised npm packages (${manifest.title ?? manifestId})`,
    severity: "critical",
    description:
      "Detects dependencies pinned to npm packages that were compromised during the referenced supply-chain incident.",
    globs: DEFAULT_LOCKFILE_GLOBS,
  };
}

async function loadManifest(
  manifestPath: string,
  context: LoadContext
): Promise<ManifestLoadResult> {
  const absolute = path.resolve(manifestPath);
  if (context.visited.has(absolute)) {
    throw new Error(`Circular signature pack extends detected at ${absolute}`);
  }
  context.visited.add(absolute);
  const manifest = await readManifest(absolute);
  const records: ManifestRecord[] = [];
  const sourcePaths: string[] = [absolute];
  const signatures: Signature[] = [];
  const resolvedProfiles = new Set<string>();

  if (manifest.id) {
    resolvedProfiles.add(manifest.id);
  }

  if (manifest.extends?.length) {
    for (const extendRef of manifest.extends) {
      if (typeof extendRef !== "string") {
        throw new Error(`Invalid extends entry in ${absolute}: ${String(extendRef)}`);
      }
      const extendProfile = getProfile(extendRef);
      const extendPath = extendProfile
        ? extendProfile.manifestPath
        : path.resolve(path.dirname(absolute), extendRef);
      const result = await loadManifest(extendPath, context);
      signatures.push(...result.signatures);
      records.push(...result.records);
      sourcePaths.push(...result.sourcePaths);
      for (const id of result.resolvedProfiles) {
        resolvedProfiles.add(id);
      }
      if (extendProfile) {
        resolvedProfiles.add(extendProfile.id);
      }
    }
  }

  const packageResult = await loadCompromisedPackages(manifest, absolute);
  if (packageResult.sourceFiles.length) {
    sourcePaths.push(...packageResult.sourceFiles);
  }
  if (packageResult.entries.length) {
    const signatureMeta = manifest.compromisedPackagesSignature
      ? { ...manifest.compromisedPackagesSignature }
      : defaultPackageSignature(manifest, absolute);
    const globs = signatureMeta.globs ?? DEFAULT_LOCKFILE_GLOBS;
    signatures.push({
      id: signatureMeta.id,
      title: signatureMeta.title,
      severity: signatureMeta.severity,
      description: signatureMeta.description,
      indicators: [
        ...globs.map((pattern) => ({ type: "glob" as const, pattern })),
        ...packageResult.entries.map((entry) => ({
          type: "package" as const,
          name: entry.name,
          version: entry.version,
        })),
      ],
    });
  }

  if (Array.isArray(manifest.signatures)) {
    signatures.push(...manifest.signatures);
  }

  records.push({ manifest, absolutePath: absolute });
  context.visited.delete(absolute);

  return {
    signatures,
    records,
    sourcePaths,
    resolvedProfiles: Array.from(resolvedProfiles),
  };
}

function materializeSignatures(signatures: Signature[]): LoadedSignature[] {
  const deduped = dedupeByKey(signatures, (signature) => signature.id);
  return deduped.map((sig) => ({
    ...sig,
    regexes: sig.indicators
      .filter((indicator): indicator is Extract<Indicator, { type: "regex" }> => indicator.type === "regex")
      .map((indicator) => new RegExp(indicator.value, "i")),
    strings: sig.indicators
      .filter((indicator): indicator is Extract<Indicator, { type: "string" }> => indicator.type === "string")
      .map((indicator) => indicator.value.toLowerCase()),
    globs: sig.indicators
      .filter((indicator): indicator is Extract<Indicator, { type: "glob" }> => indicator.type === "glob")
      .map((indicator) => indicator.pattern),
    hashes: sig.indicators
      .filter((indicator): indicator is Extract<Indicator, { type: "sha256" }> => indicator.type === "sha256")
      .map((indicator) => indicator.value.toLowerCase()),
    packages: sig.indicators.filter(
      (indicator): indicator is Extract<Indicator, { type: "package" }> => indicator.type === "package"
    ),
  }));
}

function collectSources(records: ManifestRecord[]): string[] {
  const sources: string[] = [];
  for (const record of records) {
    if (Array.isArray(record.manifest.sources)) {
      for (const source of record.manifest.sources) {
        sources.push(source);
      }
    }
  }
  return dedupeByKey(sources, (item) => item);
}

function resolveSummary(
  profileId: string | undefined,
  result: ManifestLoadResult
): SignaturePackSummary {
  const manifests = result.records;
  const primary = manifests[manifests.length - 1]?.manifest;
  const sources = collectSources(manifests);
  return {
    profileId,
    manifestId: primary?.id,
    title: primary?.title,
    summary: primary?.summary,
    updated: primary?.updated,
    sources,
    resolvedProfiles: dedupeByKey(result.resolvedProfiles, (id) => id),
  };
}

export function getDefaultProfileId(): string {
  return getDefaultProfile().id;
}

export async function loadSignatures(
  options: LoadSignaturesOptions = {}
): Promise<LoadedSignaturePack> {
  const profileId = options.profileId ?? getDefaultProfileId();
  let manifestPath: string;
  if (options.signatureFile) {
    manifestPath = path.resolve(options.signatureFile);
  } else {
    const profile = getProfile(profileId);
    if (!profile) {
      const available = listProfiles()
        .map((entry) => entry.id)
        .join(", ");
      throw new Error(
        `Unknown threat profile "${profileId}". Available profiles: ${available}`
      );
    }
    manifestPath = profile.manifestPath;
  }

  const result = await loadManifest(manifestPath, { visited: new Set() });
  const signatures = materializeSignatures(result.signatures);
  const sourcePaths = dedupeByKey(result.sourcePaths, (p) => p);
  const summary = resolveSummary(options.signatureFile ? undefined : profileId, result);
  return { sourcePaths, signatures, summary };
}

export { listProfiles, getProfile, getDefaultProfile } from "./registry";
export type { ThreatProfile } from "./registry";
