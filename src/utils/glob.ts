import path from "node:path";

/** Convert a glob pattern (supports **, *, ?) into a case-insensitive regular expression. */
export function globToRegExp(glob: string): RegExp {
  const normalized = glob.replace(/\\/g, "/");
  let regex = "^";
  for (let i = 0; i < normalized.length; i += 1) {
    const char = normalized[i];
    if (char === "*") {
      const next = normalized[i + 1];
      if (next === "*") {
        const after = normalized[i + 2];
        if (after === "/") {
          regex += "(?:.*/)?";
          i += 2;
        } else {
          regex += ".*";
          i += 1;
        }
      } else {
        regex += "[^/]*";
      }
    } else if (char === "?") {
      regex += ".";
    } else if (".+^${}()|[]".includes(char)) {
      regex += `\\${char}`;
    } else {
      regex += char;
    }
  }
  regex += "$";
  return new RegExp(regex, "i");
}

export function matchGlob(targetPath: string, globPattern: string): boolean {
  const normalizedPath = targetPath.split(path.sep).join("/");
  return globToRegExp(globPattern).test(normalizedPath);
}
