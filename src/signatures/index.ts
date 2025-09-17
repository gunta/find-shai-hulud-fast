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

interface ThreatDefinition {
  id: string;
  title: string;
  summary?: string;
  signatureIds?: string[];
  sources?: string[];
  profiles?: string[];
  tags?: string[];
}

export interface SignatureThreat {
  id: string;
  title: string;
  summary?: string;
  sources?: string[];
  profiles?: string[];
  tags?: string[];
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
  threatsFile?: string;
  threats?: ThreatDefinition[];
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
  threats: ThreatDefinition[];
}

export interface CompromisedPackageEntry {
  name: string;
  version?: string;
  versions?: string[];
}

interface ResolvedCompromisedPackage {
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
  threats: SignatureThreat[];
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

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values));
}

const canonicalizeVersion = (version: string): string => version.trim();

function mergeStringArrays(...arrays: (string[] | undefined)[]): string[] | undefined {
  const merged: string[] = [];
  for (const array of arrays) {
    if (!array) continue;
    for (const value of array) {
      if (typeof value === "string") {
        merged.push(value);
      }
    }
  }
  return merged.length ? uniqueStrings(merged) : undefined;
}

function mergeThreatLists(threats: ThreatDefinition[]): ThreatDefinition[] {
  const map = new Map<string, ThreatDefinition>();
  for (const threat of threats) {
    if (!threat.id) continue;
    const existing = map.get(threat.id);
    if (existing) {
      map.set(threat.id, {
        ...existing,
        ...threat,
        signatureIds: mergeStringArrays(existing.signatureIds, threat.signatureIds),
        sources: mergeStringArrays(existing.sources, threat.sources),
        profiles: mergeStringArrays(existing.profiles, threat.profiles),
        tags: mergeStringArrays(existing.tags, threat.tags),
      });
    } else {
      map.set(threat.id, {
        ...threat,
        signatureIds: threat.signatureIds ? uniqueStrings(threat.signatureIds) : undefined,
        sources: threat.sources ? uniqueStrings(threat.sources) : undefined,
        profiles: threat.profiles ? uniqueStrings(threat.profiles) : undefined,
        tags: threat.tags ? uniqueStrings(threat.tags) : undefined,
      });
    }
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
): Promise<{ entries: ResolvedCompromisedPackage[]; sourceFiles: string[] }> {
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
        if (!pkg || typeof pkg !== "object") continue;
        const name = (pkg as { name?: unknown }).name;
        if (typeof name !== "string") continue;
        const versions: string[] = [];
        const singleVersion = (pkg as { version?: unknown }).version;
        if (typeof singleVersion === "string") {
          versions.push(singleVersion);
        }
        const multiple = (pkg as { versions?: unknown }).versions;
        if (Array.isArray(multiple)) {
          for (const version of multiple) {
            if (typeof version === "string") {
              versions.push(version);
            }
          }
        }
        for (const version of versions) {
          const trimmed = version.trim();
          if (!trimmed) continue;
          entries.push({ name, version: trimmed });
        }
      }
    }
  }
  if (Array.isArray(manifest.compromisedPackages)) {
    for (const pkg of manifest.compromisedPackages) {
      if (!pkg || typeof pkg !== "object") continue;
      const name = (pkg as { name?: unknown }).name;
      if (typeof name !== "string") continue;
      const versions: string[] = [];
      const singleVersion = (pkg as { version?: unknown }).version;
      if (typeof singleVersion === "string") {
        versions.push(singleVersion);
      }
      const multiple = (pkg as { versions?: unknown }).versions;
      if (Array.isArray(multiple)) {
        for (const version of multiple) {
          if (typeof version === "string") {
            versions.push(version);
          }
        }
      }
      for (const version of versions) {
        const trimmed = version.trim();
        if (!trimmed) continue;
        entries.push({ name, version: trimmed });
      }
    }
  }
  const normalized: ResolvedCompromisedPackage[] = entries
    .map((entry) => {
      if (typeof entry.name !== "string" || typeof entry.version !== "string") {
        return null;
      }
      const trimmed = canonicalizeVersion(entry.version);
      if (!trimmed) return null;
      return { name: entry.name, version: trimmed };
    })
    .filter((entry): entry is ResolvedCompromisedPackage => entry !== null);

  return {
    entries: dedupeByKey(normalized, (entry) => `${entry.name}@${entry.version}`),
    sourceFiles,
  };
}

interface ThreatFilePayload {
  threats?: ThreatDefinition[];
}

async function loadThreats(
  manifest: SignaturePackManifest,
  manifestPath: string
): Promise<{ threats: ThreatDefinition[]; sourceFiles: string[] }> {
  const threats: ThreatDefinition[] = [];
  const sourceFiles: string[] = [];
  const manifestDir = path.dirname(manifestPath);

  const pushThreat = (candidate: unknown) => {
    if (!candidate || typeof candidate !== "object") return;
    const entry = candidate as Partial<ThreatDefinition>;
    if (typeof entry.id !== "string" || typeof entry.title !== "string") {
      return;
    }
    const normalized: ThreatDefinition = {
      id: entry.id,
      title: entry.title,
      summary: typeof entry.summary === "string" ? entry.summary : undefined,
      signatureIds: Array.isArray(entry.signatureIds)
        ? entry.signatureIds.filter((id): id is string => typeof id === "string")
        : undefined,
      sources: Array.isArray(entry.sources)
        ? entry.sources.filter((src): src is string => typeof src === "string")
        : undefined,
      profiles: Array.isArray(entry.profiles)
        ? entry.profiles.filter((profile): profile is string => typeof profile === "string")
        : undefined,
      tags: Array.isArray(entry.tags)
        ? entry.tags.filter((tag): tag is string => typeof tag === "string")
        : undefined,
    };
    threats.push(normalized);
  };

  if (manifest.threatsFile) {
    const filePath = path.resolve(manifestDir, manifest.threatsFile);
    const content = await fs.readFile(filePath, "utf8");
    sourceFiles.push(filePath);
    const parsed = JSON.parse(content) as ThreatFilePayload;
    if (Array.isArray(parsed.threats)) {
      parsed.threats.forEach(pushThreat);
    }
  }

  if (Array.isArray(manifest.threats)) {
    manifest.threats.forEach(pushThreat);
  }

  return { threats: mergeThreatLists(threats), sourceFiles };
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
  const aggregatedThreats: ThreatDefinition[] = [];

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
      aggregatedThreats.push(...result.threats);
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
        ...packageResult.entries.map(
          (entry): Extract<Indicator, { type: "package" }> => ({
            type: "package",
            name: entry.name,
            version: entry.version,
          })
        ),
      ],
    });
  }

  if (Array.isArray(manifest.signatures)) {
    signatures.push(...manifest.signatures);
  }

  const threatResult = await loadThreats(manifest, absolute);
  if (threatResult.sourceFiles.length) {
    sourcePaths.push(...threatResult.sourceFiles);
  }
  aggregatedThreats.push(...threatResult.threats);

  records.push({ manifest, absolutePath: absolute });
  context.visited.delete(absolute);

  return {
    signatures,
    records,
    sourcePaths,
    resolvedProfiles: Array.from(resolvedProfiles),
    threats: mergeThreatLists(aggregatedThreats),
  };
}

function buildThreatMap(
  signatures: Signature[],
  threats: ThreatDefinition[]
): Map<string, SignatureThreat[]> {
  const signatureIds = new Set(signatures.map((sig) => sig.id));
  const map = new Map<string, SignatureThreat[]>();
  for (const threat of threats) {
    if (!threat.id || !threat.title) continue;
    let targetIds: string[] | undefined;
    if (Array.isArray(threat.signatureIds) && threat.signatureIds.length) {
      targetIds = threat.signatureIds.filter((id) => typeof id === "string" && signatureIds.has(id));
    } else {
      const prefix = `${threat.id}:`;
      targetIds = Array.from(signatureIds).filter((id) => id.startsWith(prefix));
    }
    if (!targetIds.length) continue;
    const threatRef: SignatureThreat = {
      id: threat.id,
      title: threat.title,
      summary: threat.summary,
      sources: threat.sources,
      profiles: threat.profiles,
      tags: threat.tags,
    };
    for (const sigId of targetIds) {
      let existing = map.get(sigId);
      if (!existing) {
        existing = [];
        map.set(sigId, existing);
      }
      if (!existing.some((entry) => entry.id === threatRef.id)) {
        existing.push(threatRef);
      }
    }
  }
  return map;
}

function materializeSignatures(
  signatures: Signature[],
  threatMap: Map<string, SignatureThreat[]>
): LoadedSignature[] {
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
    packages: sig.indicators
      .filter(
        (indicator): indicator is Extract<Indicator, { type: "package" }> => indicator.type === "package"
      )
      .map((pkg): Extract<Indicator, { type: "package" }> => ({
        type: "package",
        name: pkg.name,
        version: canonicalizeVersion(pkg.version),
      }))
      .filter((pkg) => pkg.version.length > 0),
    threats: threatMap.get(sig.id) ?? [],
  }));
}

function collectSources(records: ManifestRecord[], threats: ThreatDefinition[]): string[] {
  const sources: string[] = [];
  for (const record of records) {
    if (Array.isArray(record.manifest.sources)) {
      for (const source of record.manifest.sources) {
        sources.push(source);
      }
    }
  }
  for (const threat of threats) {
    if (Array.isArray(threat.sources)) {
      for (const source of threat.sources) {
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
  const sources = collectSources(manifests, result.threats);
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
  const threatMap = buildThreatMap(result.signatures, result.threats);
  const signatures = materializeSignatures(result.signatures, threatMap);
  const sourcePaths = dedupeByKey(result.sourcePaths, (p) => p);
  const summary = resolveSummary(options.signatureFile ? undefined : profileId, result);
  return { sourcePaths, signatures, summary };
}

export { listProfiles, getProfile, getDefaultProfile } from "./registry";
export type { ThreatProfile } from "./registry";
