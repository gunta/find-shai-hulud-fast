import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import { loadSignatures } from "../signatures/index";
import type { LoadedSignature } from "../signatures/index";
import { Metrics } from "../telemetry";
import { Logger } from "../utils/logger";

const workerScript = new URL("./worker.ts", import.meta.url).href;

interface ScanOptions {
  paths: string[];
  defaultPaths: boolean;
  maxDepth?: number;
  exclude?: string[];
  threads?: number;
  signatureFile?: string;
  maxBytes?: number;
  logger: Logger;
  metrics: Metrics;
}

export interface Detection {
  path: string;
  signatureId: string;
  severity: string;
  title: string;
  description: string;
  indicatorType: string;
  indicatorValue: string;
}

export interface ScanSummary {
  detections: Detection[];
  errors: { path: string; error: string }[];
  scannedFiles: number;
  bytesScanned: number;
  durationMs: number;
}

interface WorkerJob {
  message: { type: "scan"; path: string; size: number };
  resolve: (value: WorkerResult) => void;
  reject: (error: Error) => void;
}

interface WorkerResult {
  type: "result";
  path: string;
  bytesRead: number;
  matches: Array<{
    signatureId: string;
    title: string;
    severity: string;
    description: string;
    indicatorType: string;
    indicatorValue: string;
  }>;
  error?: string;
}

interface WorkerRecord {
  worker: Worker;
  busy: boolean;
  currentJob?: WorkerJob;
}

class WorkerPool {
  private workers: WorkerRecord[] = [];
  private queue: WorkerJob[] = [];
  private signatures: LoadedSignature[];
  private maxBytes: number;
  constructor(size: number, signatures: LoadedSignature[], maxBytes: number) {
    this.signatures = signatures;
    this.maxBytes = maxBytes;
    for (let i = 0; i < size; i += 1) {
      this.workers.push(this.spawnWorker());
    }
  }

  private spawnWorker(): WorkerRecord {
    const worker = new Worker(workerScript, { type: "module" });
    const record: WorkerRecord = { worker, busy: false };
    worker.postMessage({ type: "init", signatures: this.signatures, maxBytes: this.maxBytes });
    worker.onmessage = (event: MessageEvent<WorkerResult>) => {
      const job = record.currentJob;
      record.currentJob = undefined;
      record.busy = false;
      if (!job) return;
      job.resolve(event.data);
      this.dispatch();
    };
    worker.onerror = (event) => {
      const job = record.currentJob;
      record.currentJob = undefined;
      record.busy = false;
      if (job) {
        job.reject(event.error ?? new Error(String(event.message)));
      }
      this.dispatch();
    };
    return record;
  }

  submit(job: WorkerJob) {
    this.queue.push(job);
    this.dispatch();
  }

  private dispatch() {
    for (const record of this.workers) {
      if (record.busy) continue;
      const job = this.queue.shift();
      if (!job) break;
      record.currentJob = job;
      record.busy = true;
      record.worker.postMessage(job.message);
    }
  }

  async drain() {
    await Promise.all(
      this.workers.map(
        (record) =>
          new Promise<void>((resolve) => {
            if (!record.busy && this.queue.length === 0) {
              resolve();
              return;
            }
            const check = () => {
              if (!record.busy && this.queue.length === 0) {
                resolve();
              } else {
                setTimeout(check, 50);
              }
            };
            check();
          })
      )
    );
  }

  async terminate() {
    for (const record of this.workers) {
      record.worker.postMessage({ type: "shutdown" });
    }
  }

  queueSize() {
    return this.queue.length;
  }

  busyCount() {
    return this.workers.filter((w) => w.busy).length;
  }
}

async function* walkPaths(paths: string[], options: { maxDepth?: number; exclude?: string[] }) {
  const stack: Array<{ path: string; depth: number }> = [];
  for (const p of paths) {
    stack.push({ path: p, depth: 0 });
  }
  while (stack.length) {
    const { path: current, depth } = stack.pop()!;
    let stats;
    try {
      stats = await fs.lstat(current);
    } catch (error) {
      yield { path: current, error: error instanceof Error ? error.message : String(error) };
      continue;
    }

    if (stats.isSymbolicLink()) continue;

    if (stats.isDirectory()) {
      if (options.maxDepth !== undefined && depth > options.maxDepth) {
        continue;
      }
      let entries: string[] = [];
      try {
        entries = await fs.readdir(current);
      } catch (error) {
        yield { path: current, error: error instanceof Error ? error.message : String(error) };
        continue;
      }
      for (const entry of entries) {
        const child = path.join(current, entry);
        if (options.exclude?.some((pattern) => child.includes(pattern))) continue;
        stack.push({ path: child, depth: depth + 1 });
      }
      continue;
    }

    if (stats.isFile()) {
      yield { path: current, size: stats.size };
    }
  }
}

export async function scan(options: ScanOptions): Promise<ScanSummary> {
  const start = performance.now();
  const signaturePack = await loadSignatures(options.signatureFile);
  const signatures = signaturePack.signatures;
  const signatureSource = signaturePack.sourcePath;
  const threads =
    options.threads && options.threads > 0
      ? options.threads
      : Math.min(Math.max(2, os.cpus().length - 1), 32);
  const maxBytes = options.maxBytes ?? 5 * 1024 * 1024;

  const pool = new WorkerPool(threads, signatures, maxBytes);
  const detections: Detection[] = [];
  const errors: { path: string; error: string }[] = [];
  const pending = new Set<Promise<void>>();
  const maxQueue = threads * 4;

  for await (const entry of walkPaths(options.paths, {
    maxDepth: options.maxDepth,
    exclude: options.exclude,
  })) {
    if ("error" in entry) {
      errors.push({ path: entry.path, error: entry.error ?? "unknown error" });
      options.metrics.addError();
      continue;
    }
    if (entry.path === signatureSource) {
      continue;
    }

    const jobPromise = new Promise<void>((resolve, reject) => {
      pool.submit({
        message: { type: "scan", path: entry.path, size: entry.size ?? 0 },
        resolve: (result) => {
          if (result.error) {
            errors.push({ path: result.path, error: result.error });
            options.metrics.addError();
            options.logger.warn(`Error scanning ${result.path}: ${result.error}`);
          } else {
            options.metrics.addFile(result.bytesRead);
            if (result.matches.length) {
              for (const match of result.matches) {
                options.metrics.addMatch();
                detections.push({
                  path: result.path,
                  signatureId: match.signatureId,
                  severity: match.severity,
                  title: match.title,
                  description: match.description,
                  indicatorType: match.indicatorType,
                  indicatorValue: match.indicatorValue,
                });
                options.logger.trace(
                  `Match ${match.signatureId} (${match.severity}) in ${result.path} - ${match.indicatorType}: ${match.indicatorValue}`
                );
              }
            }
          }
          options.metrics.setQueueDepth(pool.queueSize());
          options.metrics.setWorkersBusy(pool.busyCount());
          resolve();
        },
        reject,
      });
    });
    jobPromise.catch((error) => {
      const reason = error instanceof Error ? error.message : String(error);
      errors.push({ path: entry.path, error: reason });
      options.metrics.addError();
      options.logger.error(`Worker failure on ${entry.path}: ${reason}`);
      options.metrics.setQueueDepth(pool.queueSize());
      options.metrics.setWorkersBusy(pool.busyCount());
    });
    pending.add(jobPromise);
    jobPromise.finally(() => pending.delete(jobPromise));

    if (pending.size >= maxQueue) {
      await Promise.race(pending);
    }

    options.metrics.setQueueDepth(pool.queueSize());
    options.metrics.setWorkersBusy(pool.busyCount());
  }

  while (pending.size) {
    await Promise.race(pending);
  }
  await pool.drain();
  await pool.terminate();

  const durationMs = performance.now() - start;

  return {
    detections,
    errors,
    scannedFiles: options.metrics.state.filesScanned,
    bytesScanned: options.metrics.state.bytesScanned,
    durationMs,
  };
}
