import { hexPainter, writeStdout, writeStderr, ansiColor, isInteractiveStdout } from "./io";

const paintPrimary = hexPainter("#a855f7", { bold: true });
const paintInfo = hexPainter("#38bdf8", { bold: true });
const paintSuccess = hexPainter("#22c55e", { bold: true });
const paintWarn = hexPainter("#facc15", { bold: true });
const paintError = hexPainter("#ef4444", { bold: true });
const paintDim = ansiColor(Bun.color("#94a3b8", "ansi_16m"), { dim: true });

export const paint = {
  bold: ansiColor("", { bold: true }),
  dim: paintDim,
  info: paintInfo,
  success: paintSuccess,
  warn: paintWarn,
  error: paintError,
  headline: paintPrimary,
};

export type LogLevel = "silent" | "info" | "debug";

export interface LoggerOptions {
  level: LogLevel;
}

const infoIcon = paintInfo("ℹ");
const warnIcon = paintWarn("⚠");
const errorIcon = paintError("✖");
const debugIcon = paintDim("∙");

export class Logger {
  private level: LogLevel;

  constructor(options: LoggerOptions) {
    this.level = options.level;
    if (isInteractiveStdout() && typeof (Bun as any).enableANSIColors === "function") {
      (Bun as any).enableANSIColors(true);
    }
  }

  setLevel(level: LogLevel) {
    this.level = level;
  }

  info(message: string) {
    if (this.level === "silent") return;
    writeStdout(`${infoIcon} ${message}\n`);
  }

  warn(message: string) {
    if (this.level === "silent") return;
    writeStdout(`${warnIcon} ${message}\n`);
  }

  error(message: string) {
    writeStderr(`${errorIcon} ${message}\n`);
  }

  debug(message: string) {
    if (this.level !== "debug") return;
    writeStdout(`${debugIcon} ${paintDim(message)}\n`);
  }
}
