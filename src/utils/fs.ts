import os from "node:os";
import path from "node:path";

const HOME = os.homedir();

export function defaultScanRoots(): string[] {
  const roots = new Set<string>();
  roots.add(HOME);

  const homeRelative = [
    ["node_modules"],
    [".npm"],
    [".pnpm"],
    [".cache", "pnpm"],
    [".yarn"],
    [".bun", "install", "cache"],
    ["Library", "Caches", "bun"],
    ["Library", "Caches", "npm"],
    ["Documents", "GitHub"],
    ["Documents", "GitHubDesktop"],
    ["Documents", "GitHub Repositories"],
    ["Documents", "Visual Studio 2022", "Projects"],
    ["Documents", "Visual Studio 2019", "Projects"],
    ["Documents", "Visual Studio 2017", "Projects"],
    ["Developer"],
    ["Developer", "Git"],
    ["Developer", "GitHub"],
    ["Development"],
    ["Development", "GitHub"],
    ["Development", "Projects"],
    ["Projects"],
    ["Projects", "GitHub"],
    ["Projects", "GitLab"],
    ["workspace"],
    ["workspaces"],
    ["Workspaces"],
    ["Code"],
    ["code"],
    ["repos"],
    ["Repos"],
    ["Repositories"],
    ["source", "repos"],
    ["src"],
    ["src", "github.com"],
    ["src", "gitlab.com"],
    ["src", "bitbucket.org"],
    ["IdeaProjects"],
    ["IntelliJIDEAProjects"],
    ["WebStormProjects"],
    ["PhpStormProjects"],
    ["PyCharmProjects"],
    ["GoLandProjects"],
    ["CLionProjects"],
    ["RiderProjects"],
    ["AndroidStudioProjects"],
    ["AppCodeProjects"],
    ["DataGripProjects"],
    ["RubyMineProjects"],
    ["Fleet", "Projects"],
    ["CursorProjects"],
    ["Documents", "VSCode"],
    ["Documents", "Visual Studio Code"],
    ["Library", "Application Support", "Code", "User", "workspaceStorage"],
    ["Library", "Application Support", "CursorAI"],
    ["Library", "Application Support", "JetBrains"],
    ["Library", "Application Support", "Code", "User", "globalStorage"],
    ["Library", "Application Support", "com.github.GitHubClient"],
  ];

  homeRelative.forEach((segments) => roots.add(path.join(HOME, ...segments)));

  [
    "/usr/local/lib/node_modules",
    "/usr/local/share/.cache/pnpm",
    "/opt/homebrew/lib/node_modules",
    "/opt/homebrew/share/.cache/pnpm",
    "/usr/lib/node_modules",
    "C:/Program Files/nodejs/node_modules",
    "C:/Program Files (x86)/nodejs/node_modules",
    "C:/ProgramData/chocolatey/lib",
  ].forEach((globalPath) => roots.add(globalPath));

  return Array.from(roots);
}

export function resolvePath(p: string): string {
  if (p.startsWith("~")) {
    return path.join(HOME, p.slice(1));
  }
  return path.resolve(p);
}
