#!/usr/bin/env bun

import { mkdir, rm, writeFile, readFile, access, copyFile } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

interface ReleaseOptions {
  bump: "major" | "minor" | "patch";
  version?: string;
  prereleaseId?: string;
  dryRun: boolean;
  skipNpm: boolean;
  skipGithub: boolean;
  skipBrew: boolean;
  skipBuild: boolean;
  skipChangelog: boolean;
  skipGit: boolean;
  npmTag?: string;
  targetBranch?: string;
  targetCommitish?: string;
  draft: boolean;
  releaseName?: string;
}

interface RepoInfo {
  owner: string;
  name: string;
  homepage: string;
  remote: string;
}

interface ArtifactDescriptor {
  platform: string;
  arch: string;
  fileName: string;
  filePath: string;
  sha256: string;
  contentType: string;
  kind: "binary" | "archive" | "npm";
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const distRoot = path.join(repoRoot, "dist");
const stagingRoot = path.join(distRoot, "staging");

function parseArgs(argv: string[]): ReleaseOptions {
  const options: ReleaseOptions = {
    bump: "patch",
    dryRun: false,
    skipNpm: false,
    skipGithub: false,
    skipBrew: false,
    skipBuild: false,
    skipChangelog: false,
    skipGit: false,
    draft: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case "--bump": {
        const value = argv[++i];
        if (!value || !["major", "minor", "patch"].includes(value)) {
          throw new Error("--bump requires one of: major | minor | patch");
        }
        options.bump = value as ReleaseOptions["bump"];
        break;
      }
      case "--version": {
        const value = argv[++i];
        if (!value) {
          throw new Error("--version requires a value");
        }
        options.version = value;
        break;
      }
      case "--pre":
      case "--prerelease": {
        const id = argv[++i];
        if (!id) {
          throw new Error("--pre/--prerelease requires an identifier (e.g. rc, beta)");
        }
        options.prereleaseId = id;
        break;
      }
      case "--dry-run":
        options.dryRun = true;
        break;
      case "--skip-publish":
        options.skipNpm = true;
        break;
      case "--skip-github":
        options.skipGithub = true;
        break;
      case "--skip-brew":
        options.skipBrew = true;
        break;
      case "--skip-build":
        options.skipBuild = true;
        break;
      case "--skip-changelog":
        options.skipChangelog = true;
        break;
      case "--skip-git":
        options.skipGit = true;
        break;
      case "--npm-tag": {
        const value = argv[++i];
        if (!value) {
          throw new Error("--npm-tag requires a value");
        }
        options.npmTag = value;
        break;
      }
      case "--target-branch": {
        const value = argv[++i];
        if (!value) {
          throw new Error("--target-branch requires a value");
        }
        options.targetBranch = value;
        break;
      }
      case "--target-commitish": {
        const value = argv[++i];
        if (!value) {
          throw new Error("--target-commitish requires a value");
        }
        options.targetCommitish = value;
        break;
      }
      case "--draft":
        options.draft = true;
        break;
      case "--release-name": {
        const value = argv[++i];
        if (!value) {
          throw new Error("--release-name requires a value");
        }
        options.releaseName = value;
        break;
      }
      default:
        throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return options;
}

async function runCommand(cmd: string, args: string[], opts: { cwd?: string; capture?: boolean; env?: Record<string, string>; quiet?: boolean } = {}) {
  const cwd = opts.cwd ?? repoRoot;
  const capture = opts.capture ?? false;

  return await new Promise<{ stdout: string; stderr: string; exitCode: number }>((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd,
      env: { ...process.env, ...opts.env },
      stdio: capture ? ["inherit", "pipe", "pipe"] : "inherit",
    });

    let stdout = "";
    let stderr = "";

    if (capture) {
      child.stdout?.on("data", (chunk) => {
        stdout += chunk.toString();
      });
      child.stderr?.on("data", (chunk) => {
        stderr += chunk.toString();
      });
    }

    child.on("error", (err) => {
      reject(err);
    });

    child.on("close", (code) => {
      resolve({ stdout: stdout.trim(), stderr: stderr.trim(), exitCode: code ?? 0 });
    });
  });
}

async function ensureCleanGit() {
  const status = await runCommand("git", ["status", "--porcelain"], { capture: true });
  if (status.exitCode !== 0) {
    throw new Error("Failed to check git status");
  }
  if (status.stdout.trim().length > 0) {
    throw new Error("Git worktree is not clean. Commit or stash changes before releasing.");
  }
}

async function readJson<T>(filePath: string): Promise<T> {
  const file = await readFile(filePath, "utf8");
  return JSON.parse(file) as T;
}

async function writeJson(filePath: string, data: unknown, dryRun: boolean) {
  const json = JSON.stringify(data, null, 2) + "\n";
  if (dryRun) {
    console.log(`[dry-run] Would write ${filePath}`);
    console.log(json);
    return;
  }
  await writeFile(filePath, json, "utf8");
}

function bumpVersion(current: string, bump: ReleaseOptions["bump"], prereleaseId?: string): string {
  const [main, pre] = current.split("-");
  const segments = main.split(".").map((part) => Number.parseInt(part, 10));
  if (segments.length !== 3 || segments.some((n) => Number.isNaN(n))) {
    throw new Error(`Unsupported version format: ${current}`);
  }
  let [major, minor, patch] = segments;

  switch (bump) {
    case "major":
      major += 1;
      minor = 0;
      patch = 0;
      break;
    case "minor":
      minor += 1;
      patch = 0;
      break;
    case "patch":
    default:
      patch += 1;
      break;
  }

  if (prereleaseId) {
    return `${major}.${minor}.${patch}-${prereleaseId}.0`;
  }

  return `${major}.${minor}.${patch}`;
}

async function determineVersion(options: ReleaseOptions, currentVersion: string): Promise<string> {
  if (options.version) {
    return options.version;
  }
  return bumpVersion(currentVersion, options.bump, options.prereleaseId);
}

async function getRepoInfo(): Promise<RepoInfo> {
  const remoteResult = await runCommand("git", ["config", "--get", "remote.origin.url"], { capture: true });
  if (remoteResult.exitCode !== 0 || !remoteResult.stdout) {
    throw new Error("Could not determine git remote origin URL");
  }

  let remote = remoteResult.stdout.trim();
  let owner: string | undefined;
  let name: string | undefined;

  if (remote.startsWith("git@github.com:")) {
    remote = remote.replace("git@github.com:", "").replace(/\.git$/, "");
    [owner, name] = remote.split("/");
  } else if (remote.startsWith("https://github.com/")) {
    remote = remote.replace("https://github.com/", "").replace(/\.git$/, "");
    [owner, name] = remote.split("/");
  }

  if (!owner || !name) {
    throw new Error(`Unsupported remote format: ${remoteResult.stdout}`);
  }

  return {
    owner,
    name,
    homepage: `https://github.com/${owner}/${name}`,
    remote: `${owner}/${name}`,
  };
}

function groupCommits(log: string) {
  type SectionKey = "breaking" | "features" | "fixes" | "docs" | "refactors" | "tests" | "chore";
  const sections: Record<SectionKey, { hash: string; subject: string }[]> = {
    breaking: [],
    features: [],
    fixes: [],
    docs: [],
    refactors: [],
    tests: [],
    chore: [],
  };

  const records = log
    .split("\u001e")
    .map((record) => record.trim())
    .filter(Boolean);

  for (const record of records) {
    const [hash, subject, body = ""] = record.split("\u001f");
    if (!hash || !subject) continue;
    const lowered = subject.toLowerCase();
    const bodyLowered = body.toLowerCase();
    const entry = { hash, subject };

    if (lowered.includes("!") || bodyLowered.includes("breaking change")) {
      sections.breaking.push(entry);
      continue;
    }
    if (lowered.startsWith("feat")) {
      sections.features.push(entry);
      continue;
    }
    if (lowered.startsWith("fix") || lowered.startsWith("bug")) {
      sections.fixes.push(entry);
      continue;
    }
    if (lowered.startsWith("docs")) {
      sections.docs.push(entry);
      continue;
    }
    if (lowered.startsWith("refactor") || lowered.startsWith("perf")) {
      sections.refactors.push(entry);
      continue;
    }
    if (lowered.startsWith("test")) {
      sections.tests.push(entry);
      continue;
    }
    sections.chore.push(entry);
  }

  return sections;
}

function formatChangelogEntry(version: string, sections: ReturnType<typeof groupCommits>): string {
  const date = new Date().toISOString().slice(0, 10);
  const lines: string[] = [`## v${version} - ${date}`, ""];

  const addSection = (title: string, entries: { hash: string; subject: string }[]) => {
    if (!entries.length) return;
    lines.push(`### ${title}`);
    for (const entry of entries) {
      lines.push(`- ${entry.subject} (${entry.hash})`);
    }
    lines.push("");
  };

  addSection("⚠️ Breaking Changes", sections.breaking);
  addSection("Features", sections.features);
  addSection("Fixes", sections.fixes);
  addSection("Docs", sections.docs);
  addSection("Refactors & Performance", sections.refactors);
  addSection("Tests", sections.tests);
  addSection("Maintenance", sections.chore);

  if (lines[lines.length - 1] !== "") {
    lines.push("");
  }

  return lines.join("\n");
}

async function buildChangelog(version: string, options: ReleaseOptions): Promise<{ entry: string; previousTag?: string }> {
  const describe = await runCommand("git", ["describe", "--tags", "--abbrev=0"], { capture: true });
  const previousTag = describe.exitCode === 0 ? describe.stdout.trim() : undefined;
  const range = previousTag ? `${previousTag}..HEAD` : "";

  const logArgs = ["log", "--pretty=format:%h\u001f%s\u001f%b\u001e"];
  if (range) {
    logArgs.splice(1, 0, range);
  }
  const log = await runCommand("git", logArgs, { capture: true });
  if (log.exitCode !== 0) {
    throw new Error("Failed to read git log for changelog generation");
  }

  const sections = groupCommits(log.stdout);
  const entry = formatChangelogEntry(version, sections);
  return { entry, previousTag };
}

async function prependFile(filePath: string, content: string, dryRun: boolean) {
  let existing = "";
  try {
    await access(filePath, fsConstants.F_OK);
    existing = await readFile(filePath, "utf8");
  } catch {
    // create new file
  }

  const next = existing ? `${content}\n${existing}` : `${content}\n`;
  if (dryRun) {
    console.log(`[dry-run] Would write ${filePath}`);
    console.log(next);
    return;
  }

  await writeFile(filePath, next, "utf8");
}

async function runChecks() {
  await runCommand("bun", ["test"]);
  await runCommand("bun", ["run", "lint"]);
}

async function cleanDist(dryRun: boolean) {
  if (dryRun) {
    console.log("[dry-run] Would clean dist/");
    return;
  }
  await rm(distRoot, { recursive: true, force: true });
  await mkdir(distRoot, { recursive: true });
  await mkdir(stagingRoot, { recursive: true });
}

async function computeSha256(filePath: string): Promise<string> {
  const file = Bun.file(filePath);
  const data = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

interface TargetDescriptor {
  target: string;
  platform: string;
  arch: string;
  binaryName: string;
  archiveExt: string;
  contentType: string;
}

const targets: TargetDescriptor[] = [
  {
    target: "bun-linux-x64",
    platform: "linux",
    arch: "x64",
    binaryName: "npm-supply-scan",
    archiveExt: "tar.gz",
    contentType: "application/gzip",
  },
  {
    target: "bun-linux-arm64",
    platform: "linux",
    arch: "arm64",
    binaryName: "npm-supply-scan",
    archiveExt: "tar.gz",
    contentType: "application/gzip",
  },
  {
    target: "bun-darwin-x64",
    platform: "macos",
    arch: "x64",
    binaryName: "npm-supply-scan",
    archiveExt: "tar.gz",
    contentType: "application/gzip",
  },
  {
    target: "bun-darwin-arm64",
    platform: "macos",
    arch: "arm64",
    binaryName: "npm-supply-scan",
    archiveExt: "tar.gz",
    contentType: "application/gzip",
  },
  {
    target: "bun-windows-x64",
    platform: "windows",
    arch: "x64",
    binaryName: "npm-supply-scan.exe",
    archiveExt: "zip",
    contentType: "application/zip",
  },
];

async function buildArtifacts(version: string, repo: RepoInfo, dryRun: boolean): Promise<ArtifactDescriptor[]> {
  if (dryRun) {
    console.log("[dry-run] Would build artifacts for all targets");
    return [];
  }

  const artifacts: ArtifactDescriptor[] = [];

  for (const target of targets) {
    const binaryFile = path.join(stagingRoot, `${target.platform}-${target.arch}`, target.binaryName);
    const binaryDir = path.dirname(binaryFile);
    await mkdir(binaryDir, { recursive: true });
    const outfile = path.join(binaryDir, target.binaryName);

    const args = ["build", "src/cli.ts", "--compile", "--target", target.target, "--outfile", outfile];
    console.log(`> bun ${args.join(" ")}`);
    const result = await runCommand("bun", args);
    if (result.exitCode !== 0) {
      throw new Error(`bun build failed for target ${target.target}`);
    }

    const archiveBaseName = `npm-supply-scan-v${version}-${target.platform}-${target.arch}.${target.archiveExt}`;
    const archivePath = path.join(distRoot, archiveBaseName);

    if (target.archiveExt === "tar.gz") {
      await runCommand("tar", ["-czf", archivePath, "-C", binaryDir, path.basename(outfile)]);
    } else {
      await runCommand("zip", ["-j", archivePath, outfile]);
    }

    const sha256 = await computeSha256(archivePath);
    artifacts.push({
      platform: target.platform,
      arch: target.arch,
      fileName: archiveBaseName,
      filePath: archivePath,
      sha256,
      contentType: target.contentType,
      kind: "archive",
    });
  }

  const packResult = await runCommand("bun", ["pm", "pack"], { capture: true });
  if (packResult.exitCode !== 0) {
    throw new Error("bun pm pack failed");
  }
  const tgzNameMatch = packResult.stdout.split("\n").find((line) => line.endsWith(".tgz"));
  if (!tgzNameMatch) {
    throw new Error("Could not find packed tarball name in bun pm pack output");
  }
  const tgzName = tgzNameMatch.trim();
  const tgzSource = path.join(repoRoot, tgzName);
  const tgzTarget = path.join(distRoot, tgzName);
  await copyFile(tgzSource, tgzTarget);
  await rm(tgzSource, { force: true });
  const npmSha = await computeSha256(tgzTarget);
  artifacts.push({
    platform: "npm",
    arch: "package",
    fileName: tgzName,
    filePath: tgzTarget,
    sha256: npmSha,
    contentType: "application/gzip",
    kind: "npm",
  });

  return artifacts;
}

function renderHomebrewFormula(version: string, artifacts: ArtifactDescriptor[], repo: RepoInfo, licenseValue?: string): string {
  const macArm = artifacts.find((a) => a.platform === "macos" && a.arch === "arm64");
  const macX64 = artifacts.find((a) => a.platform === "macos" && a.arch === "x64");
  const linuxArm = artifacts.find((a) => a.platform === "linux" && a.arch === "arm64");
  const linuxX64 = artifacts.find((a) => a.platform === "linux" && a.arch === "x64");

  if (!macArm || !macX64 || !linuxArm || !linuxX64) {
    throw new Error("Missing artifacts required for Homebrew formula");
  }

  const licenseLine = licenseValue ? `  license "${licenseValue}"` : "  license :cannot_represent # TODO: set SPDX license";

  return `class NpmSupplyScan < Formula
  desc "Lightning-fast npm supply-chain attack scanner with pluggable threat profiles"
  homepage "${repo.homepage}"
${licenseLine}
  version "${version}"

  on_macos do
    if Hardware::CPU.arm?
      url "${repo.homepage}/releases/download/v${version}/${macArm.fileName}"
      sha256 "${macArm.sha256}"
    end
    if Hardware::CPU.intel?
      url "${repo.homepage}/releases/download/v${version}/${macX64.fileName}"
      sha256 "${macX64.sha256}"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "${repo.homepage}/releases/download/v${version}/${linuxArm.fileName}"
      sha256 "${linuxArm.sha256}"
    end
    if Hardware::CPU.intel?
      url "${repo.homepage}/releases/download/v${version}/${linuxX64.fileName}"
      sha256 "${linuxX64.sha256}"
    end
  end

  def install
    bin.install "npm-supply-scan"
  end

  test do
    output = shell_output("#{bin}/npm-supply-scan --help")
    assert_match "--list-profiles", output
  end
end
`;
}

async function writeHomebrewFormula(version: string, artifacts: ArtifactDescriptor[], repo: RepoInfo, licenseValue: string | undefined, dryRun: boolean) {
  const formulaDir = path.join(repoRoot, "Formula");
  if (!dryRun) {
    await mkdir(formulaDir, { recursive: true });
  }
  const content = renderHomebrewFormula(version, artifacts, repo, licenseValue);
  const filePath = path.join(formulaDir, "npm-supply-scan.rb");
  if (dryRun) {
    console.log(`[dry-run] Would write Homebrew formula to ${filePath}`);
    console.log(content);
    return;
  }
  await writeFile(filePath, content, "utf8");
}

async function gitCommit(version: string, dryRun: boolean) {
  if (dryRun) {
    console.log("[dry-run] Would git add/commit/tag");
    return;
  }
  await runCommand("git", ["add", "package.json", "CHANGELOG.md", "Formula/npm-supply-scan.rb"], { quiet: true });
  await runCommand("git", ["commit", "-m", `chore(release): v${version}`]);
  await runCommand("git", ["tag", `v${version}`]);
}

async function gitPush(version: string, targetBranch: string | undefined, dryRun: boolean) {
  if (dryRun) {
    console.log(`[dry-run] Would push branch and tags`);
    return;
  }
  const branchResult = await runCommand("git", ["rev-parse", "--abbrev-ref", "HEAD"], { capture: true });
  if (branchResult.exitCode !== 0 || !branchResult.stdout) {
    throw new Error("Failed to determine current git branch");
  }
  const branch = targetBranch ?? branchResult.stdout.trim();
  await runCommand("git", ["push", "origin", branch]);
  await runCommand("git", ["push", "origin", `v${version}`]);
}

async function publishToNpm(version: string, options: ReleaseOptions, dryRun: boolean) {
  if (options.skipNpm) {
    console.log("Skipping npm publish");
    return;
  }

  const authToken = process.env.BUN_AUTH_TOKEN ?? process.env.NPM_TOKEN ?? process.env.NODE_AUTH_TOKEN;
  if (!authToken) {
    console.warn("No npm auth token found (BUN_AUTH_TOKEN / NPM_TOKEN / NODE_AUTH_TOKEN). Skipping npm publish.");
    return;
  }

  const args = ["publish"];
  if (dryRun) args.push("--dry-run");
  if (options.npmTag) {
    args.push("--tag", options.npmTag);
  }
  console.log(`> bun ${args.join(" ")}`);
  const result = await runCommand("bun", args, { env: { BUN_AUTH_TOKEN: authToken } });
  if (result.exitCode !== 0) {
    throw new Error("bun publish failed");
  }
}

async function createGithubRelease(version: string, notes: string, artifacts: ArtifactDescriptor[], repo: RepoInfo, options: ReleaseOptions) {
  if (options.skipGithub) {
    console.log("Skipping GitHub release");
    return;
  }
  const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
  if (!token) {
    console.warn("No GITHUB_TOKEN/GH_TOKEN provided. Skipping GitHub release.");
    return;
  }

  const releaseName = options.releaseName ?? `npm-supply-scan v${version}`;
  const targetCommitish = options.targetCommitish ?? (await runCommand("git", ["rev-parse", "HEAD"], { capture: true })).stdout;

  const createResponse = await fetch(`https://api.github.com/repos/${repo.remote}/releases`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "User-Agent": "npm-supply-scan-release-script",
      Accept: "application/vnd.github+json",
    },
    body: JSON.stringify({
      tag_name: `v${version}`,
      target_commitish: targetCommitish,
      name: releaseName,
      body: notes,
      draft: options.draft,
      prerelease: Boolean(options.prereleaseId),
    }),
  });

  if (!createResponse.ok) {
    const text = await createResponse.text();
    throw new Error(`Failed to create GitHub release: ${createResponse.status} ${createResponse.statusText} -> ${text}`);
  }

  const releaseData = await createResponse.json();
  const uploadUrl = (releaseData.upload_url as string).replace("{?name,label}", "");

  for (const artifact of artifacts) {
    if (artifact.kind === "npm") continue;
    const data = await Bun.file(artifact.filePath).arrayBuffer();
    const uploadResponse = await fetch(`${uploadUrl}?name=${encodeURIComponent(artifact.fileName)}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": artifact.contentType,
        "Content-Length": data.byteLength.toString(),
      },
      body: data,
    });

    if (!uploadResponse.ok) {
      const text = await uploadResponse.text();
      throw new Error(`Failed to upload ${artifact.fileName} to GitHub release: ${uploadResponse.status} ${uploadResponse.statusText} -> ${text}`);
    }
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const pkgPath = path.join(repoRoot, "package.json");
  const pkg = await readJson<Record<string, any>>(pkgPath);

  if (!options.skipGit && !options.dryRun) {
    await ensureCleanGit();
  }

  const repo = await getRepoInfo();
  const targetVersion = await determineVersion(options, pkg.version as string);

  if (!options.skipChangelog) {
    const changelog = await buildChangelog(targetVersion, options);
    await prependFile(path.join(repoRoot, "CHANGELOG.md"), changelog.entry, options.dryRun);
  }

  pkg.version = targetVersion;
  pkg.publishConfig = pkg.publishConfig ?? { access: "public", registry: "https://registry.npmjs.org" };
  await writeJson(pkgPath, pkg, options.dryRun);

  await cleanDist(options.dryRun);

  if (!options.skipBuild && !options.dryRun) {
    await runChecks();
  }

  const artifacts = options.skipBuild ? [] : await buildArtifacts(targetVersion, repo, options.dryRun);

  const licenseValue = typeof pkg.license === "string" ? pkg.license : undefined;
  if (!options.skipBrew && artifacts.length) {
    await writeHomebrewFormula(targetVersion, artifacts, repo, licenseValue, options.dryRun);
  }

  if (!options.skipGit) {
    await gitCommit(targetVersion, options.dryRun);
    await gitPush(targetVersion, options.targetBranch, options.dryRun);
  }

  if (!options.skipNpm) {
    await publishToNpm(targetVersion, options, options.dryRun);
  }

  let latestNotes = `## v${targetVersion}`;
  if (!options.skipChangelog && !options.dryRun) {
    try {
      const changelogContent = await readFile(path.join(repoRoot, "CHANGELOG.md"), "utf8");
      const marker = "\n## v";
      const idx = changelogContent.indexOf(marker, 1);
      latestNotes = (idx === -1 ? changelogContent : changelogContent.slice(0, idx)).trim();
    } catch (err) {
      console.warn("Unable to read CHANGELOG.md for release notes", err);
    }
  }

  if (!options.dryRun) {
    await createGithubRelease(targetVersion, latestNotes, artifacts, repo, options);
  } else {
    console.log("[dry-run] Would create GitHub release with notes:\n", latestNotes);
  }

  console.log(`Release v${targetVersion} prepared successfully.`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
