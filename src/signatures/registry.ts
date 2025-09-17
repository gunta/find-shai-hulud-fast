import { fileURLToPath } from "node:url";

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

const profiles: ThreatProfile[] = [
  {
    id: "latest",
    title: "Latest npm supply-chain threats",
    summary:
      "Aggregated signatures for high-impact npm supply-chain incidents observed over the last 12 months, kept up to date with newly disclosed threats.",
    manifestPath: fileURLToPath(new URL("./packs/latest/pack.json", import.meta.url)),
    default: true,
    tags: ["latest", "curated", "default"],
    updated: "2025-09-16",
    aliases: ["default", "rolling"],
  },
  {
    id: "shai-hulud",
    title: "Shai hulud npm supply-chain attack (JFrog, Sep 2025)",
    summary:
      "Full fast scanner profile focused on the shai hulud malware family, including lockfile indicators and payload hashes.",
    manifestPath: fileURLToPath(new URL("./packs/shai-hulud/pack.json", import.meta.url)),
    tags: ["malware", "jfrog", "2025"],
    updated: "2025-09-16",
    aliases: ["shai", "shai-hulud-fast"],
  },
];

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
