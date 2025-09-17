#!/usr/bin/env bun
import os from "node:os";
import path from "node:path";
import { scan } from "./scanner/index";
import { defaultScanRoots, resolvePath } from "./utils/fs";
import { Metrics, renderSnapshot, clearTelemetryLine } from "./telemetry";
import { Logger, paint, LogLevel } from "./utils/logger";
import { printDetections, printSummary, promptRemediation } from "./reporters/console";
import { emitJson } from "./reporters/json";
import { cloneRepository } from "./remote";
import { writeStdout, writeStderr, isInteractiveStdout } from "./utils/io";

interface CliOptions {
  help?: boolean;
  version?: boolean;
  defaultPaths: boolean;
  paths: string[];
  exclude: string[];
  threads?: number;
  maxDepth?: number;
  cloneUrl?: string;
  cloneBranch?: string;
  keepTemp?: boolean;
  json?: boolean;
  noMetrics?: boolean;
  signatureFile?: string;
  logLevel: LogLevel;
}

const VERSION = "0.1.0";

function printHelp() {
  const out = `Shai Hulud Scanner v${VERSION}\n\n` +
    `Usage: shai-scan [options] [paths...]\n\n` +
    `Options:\n` +
    `  --default-paths        Include standard npm/pnpm/yarn/bun caches\n` +
    `  --path <dir>           Additional directory to scan (repeatable)\n` +
    `  --exclude <pattern>    Substring filter to skip paths (repeatable)\n` +
    `  --threads <n>          Override automatic worker count\n` +
    `  --max-depth <n>        Limit directory traversal depth\n` +
    `  --clone-url <url>      Clone and scan remote Git repository\n` +
    `  --clone-branch <ref>   Checkout specific ref for remote scan\n` +
    `  --keep-temp            Keep cloned repository directory\n` +
    `  --signature-file <p>   Load custom IOC signature file\n` +
    `  --json                 Emit JSON report instead of console summary\n` +
    `  --no-metrics           Disable live telemetry output\n` +
    `  --log-level <level>    Log level (silent|info|debug|trace)\n` +
    `  --version              Show version\n` +
    `  --help                 Show this help message\n`;
  writeStdout(out);
}

function requireValue(argv: string[], index: number, flag: string): string {
  const value = argv[index];
  if (value === undefined) {
    throw new Error(`Missing value for ${flag}`);
  }
  return value;
}

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {
    defaultPaths: false,
    paths: [],
    exclude: [],
    logLevel: (process.env.SHAI_SCAN_LOG_LEVEL as LogLevel) || "info",
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case "--help":
        options.help = true;
        break;
      case "--version":
        options.version = true;
        break;
      case "--default-paths":
        options.defaultPaths = true;
        break;
      case "--path":
        options.paths.push(requireValue(argv, ++i, "--path"));
        break;
      case "--exclude":
        options.exclude.push(requireValue(argv, ++i, "--exclude"));
        break;
      case "--threads":
        options.threads = Number.parseInt(requireValue(argv, ++i, "--threads"), 10);
        break;
      case "--max-depth":
        options.maxDepth = Number.parseInt(requireValue(argv, ++i, "--max-depth"), 10);
        break;
      case "--clone-url":
        options.cloneUrl = requireValue(argv, ++i, "--clone-url");
        break;
      case "--clone-branch":
        options.cloneBranch = requireValue(argv, ++i, "--clone-branch");
        break;
      case "--keep-temp":
        options.keepTemp = true;
        break;
      case "--json":
        options.json = true;
        break;
      case "--no-metrics":
        options.noMetrics = true;
        break;
      case "--signature-file":
        options.signatureFile = requireValue(argv, ++i, "--signature-file");
        break;
      case "--log-level":
        options.logLevel = requireValue(argv, ++i, "--log-level") as LogLevel;
        break;
      default:
        if (arg.startsWith("-")) {
          throw new Error(`Unknown option: ${arg}`);
        }
        options.paths.push(arg);
    }
  }

  if (options.threads !== undefined && (!Number.isFinite(options.threads) || options.threads <= 0)) {
    throw new Error("--threads must be a positive number");
  }
  if (options.maxDepth !== undefined && options.maxDepth < 0) {
    throw new Error("--max-depth must be zero or greater");
  }

  return options;
}

async function main() {
  try {
    const argv = Bun.argv.slice(2);
    const options = parseArgs(argv);

    if (options.help) {
      printHelp();
      return;
    }
    if (options.version) {
      writeStdout(`${VERSION}\n`);
      return;
    }

    const logger = new Logger({ level: options.logLevel });
    const metrics = new Metrics();

    const telemetryIntervalMs = Number.parseInt(process.env.SHAI_SCAN_TICK ?? "750", 10);
    let telemetryTimer: ReturnType<typeof setInterval> | null = null;
    if (!options.noMetrics && isInteractiveStdout()) {
      telemetryTimer = setInterval(() => {
        const snapshot = metrics.snapshot();
        renderSnapshot(snapshot);
      }, telemetryIntervalMs);
    }

    const scanPaths = new Set<string>();
    if (options.defaultPaths || options.paths.length === 0) {
      defaultScanRoots().forEach((p) => scanPaths.add(resolvePath(p)));
    }
    options.paths.forEach((p) => scanPaths.add(resolvePath(p)));

    let clonedRepoCleanup: (() => Promise<void>) | null = null;
    if (options.cloneUrl) {
      const clone = await cloneRepository({
        url: options.cloneUrl,
        branch: options.cloneBranch,
        keepTemp: options.keepTemp,
        logger,
      });
      scanPaths.add(clone.path);
      clonedRepoCleanup = clone.cleanup;
    }

    metrics.markStart();
    logger.info(
      `Scanning with ${os.cpus().length} logical cores, ${scanPaths.size} path(s).`
    );
    const summary = await scan({
      paths: Array.from(scanPaths),
      defaultPaths: options.defaultPaths,
      maxDepth: options.maxDepth,
      exclude: options.exclude,
      threads: options.threads,
      signatureFile: options.signatureFile,
      logger,
      metrics,
    });

    if (telemetryTimer) {
      clearInterval(telemetryTimer);
      clearTelemetryLine();
    }

    if (summary.detections.length && !options.json && isInteractiveStdout()) {
      printDetections(summary.detections);
      await promptRemediation(summary.detections);
    }

    if (options.json) {
      emitJson(summary);
    } else {
      if (!summary.detections.length) {
        writeStdout(`\n${paint.success("No shai hulud indicators detected.")}\n`);
      }
      printSummary(summary);
      if (summary.errors.length) {
        summary.errors.slice(0, 5).forEach((err) => {
          logger.warn(`Failed to scan ${err.path}: ${err.error}`);
        });
        if (summary.errors.length > 5) {
          logger.warn(
            `Additional ${summary.errors.length - 5} errors suppressed; rerun with --log-level trace for details.`
          );
        }
      }
    }

    if (clonedRepoCleanup) {
      await clonedRepoCleanup();
    }

    process.exitCode = summary.detections.length ? 2 : summary.errors.length ? 1 : 0;
  } catch (error) {
    clearTelemetryLine();
    const message = error instanceof Error ? error.message : String(error);
    writeStderr(`${paint.error("Fatal:")} ${message}\n`);
    process.exitCode = 1;
  }
}

await main();
