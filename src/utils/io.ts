import type { BunFile } from "bun";

const stdout = Bun.stdout as BunFile;
const stderr = Bun.stderr as BunFile;
const stdin = Bun.stdin as BunFile;

const NO_COLOR = Bun.env.NO_COLOR === "1" || Bun.env.NO_COLOR === "true";

export function isInteractiveStdout(): boolean {
  if (typeof (stdout as any)?.isTTY === "boolean") {
    return (stdout as any).isTTY;
  }
  if (typeof process.stdout?.isTTY === "boolean") {
    return process.stdout.isTTY;
  }
  return true;
}

function write(stream: BunFile, text: string): Promise<number> {
  return Bun.write(stream, text).catch(() => 0);
}

export function writeStdout(text: string): Promise<number> {
  return write(stdout, text);
}

export function writeStderr(text: string): Promise<number> {
  return write(stderr, text);
}

export function ansiColor(code: string | undefined, opts?: { bold?: boolean; dim?: boolean }) {
  if (NO_COLOR || !isInteractiveStdout()) {
    return (value: string) => value;
  }
  const colorCode = code ?? "";
  const bold = opts?.bold ? "\u001b[1m" : "";
  const dim = opts?.dim ? "\u001b[2m" : "";
  const reset = "\u001b[0m";
  return (value: string) => `${bold}${dim}${colorCode}${value}${reset}`;
}

export function hexPainter(hex: string, opts?: { bold?: boolean; dim?: boolean }) {
  const code = Bun.color(hex, "ansi-16m") ?? hex;
  return ansiColor(code, opts);
}

const decoder = new TextDecoder();

export async function readLine(promptText: string): Promise<string> {
  writeStdout(promptText);
  const reader = stdin.stream().getReader();
  let collected = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done || !value) break;
    collected += decoder.decode(value, { stream: true });
    const newlineIndex = collected.indexOf("\n");
    if (newlineIndex !== -1) {
      const line = collected.slice(0, newlineIndex).replace(/\r?$/, "");
      reader.releaseLock();
      return line;
    }
  }
  reader.releaseLock();
  return collected.replace(/\r?$/, "");
}
