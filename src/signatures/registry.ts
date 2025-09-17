import { fileURLToPath } from "node:url";
import { readJsonFile } from "../utils/json-cache";

export interface ThreatProfile {
  id: string;
  title: string;
  summary?: string;
  manifestPath: string;
  default?: boolean;
  tags?: string[];
  updated?: string;
  aliases?: string[];
}

interface ProfilesDocumentEntry {
  id: string;
  title: string;
  summary?: string;
  manifestPath: string;
  default?: boolean;
  tags?: string[];
  updated?: string;
  aliases?: string[];
}

interface ProfilesDocument {
  profiles?: ProfilesDocumentEntry[];
}

const profilesConfigPath = fileURLToPath(new URL("./profiles.json", import.meta.url));
const profilesDocument = await readJsonFile<ProfilesDocument>(profilesConfigPath);

const profiles: ThreatProfile[] = (profilesDocument.profiles ?? []).map((entry) => ({
  id: entry.id,
  title: entry.title,
  summary: entry.summary,
  manifestPath: fileURLToPath(new URL(entry.manifestPath, import.meta.url)),
  default: entry.default,
  tags: entry.tags,
  updated: entry.updated,
  aliases: entry.aliases,
}));

if (!profiles.length) {
  throw new Error(`No threat profiles configured in ${profilesConfigPath}`);
}

export function listProfiles(): ThreatProfile[] {
  return profiles.map((profile) => ({ ...profile }));
}

export function getProfile(id: string): ThreatProfile | undefined {
  const normalized = id.trim().toLowerCase();
  return profiles.find((profile) => {
    if (profile.id.toLowerCase() === normalized) return true;
    if (!profile.aliases) return false;
    return profile.aliases.some((alias) => alias.toLowerCase() === normalized);
  });
}

export function getDefaultProfile(): ThreatProfile {
  return profiles.find((profile) => profile.default) ?? profiles[0];
}
