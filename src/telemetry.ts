import os from "node:os";
import { paint } from "./utils/logger";
import { writeStdout } from "./utils/io";

export interface TelemetrySnapshot {
  filesScanned: number;
  matches: number;
  bytesScanned: number;
  queueDepth: number;
  workersBusy: number;
  elapsedMs: number;
  filesPerSecond: number;
  mbPerSecond: number;
  cpuPercent: number;
  errors: number;
}

export interface MetricsState {
  filesScanned: number;
  bytesScanned: number;
  matches: number;
  errors: number;
  queueDepth: number;
  workersBusy: number;
  startTime: number;
}

export class Metrics {
  state: MetricsState;
  private cpuLastUsage = process.cpuUsage();
  private cpuLastTime = performance.now();

  constructor() {
    this.state = {
      filesScanned: 0,
      bytesScanned: 0,
      matches: 0,
      errors: 0,
      queueDepth: 0,
      workersBusy: 0,
      startTime: performance.now(),
    };
  }

  markStart() {
    this.state.startTime = performance.now();
  }

  addFile(bytes: number) {
    this.state.filesScanned += 1;
    this.state.bytesScanned += bytes;
  }

  addMatch() {
    this.state.matches += 1;
  }

  addError() {
    this.state.errors += 1;
  }

  setQueueDepth(depth: number) {
    this.state.queueDepth = depth;
  }

  setWorkersBusy(count: number) {
    this.state.workersBusy = count;
  }

  snapshot(): TelemetrySnapshot {
    const now = performance.now();
    const elapsedMs = now - this.state.startTime;
    const filesPerSecond =
      elapsedMs > 0 ? (this.state.filesScanned / elapsedMs) * 1000 : 0;
    const mbPerSecond =
      elapsedMs > 0 ? (this.state.bytesScanned / 1024 / 1024) / (elapsedMs / 1000) : 0;

    const cpuSnapshot = process.cpuUsage();
    const cpuDiffUser = cpuSnapshot.user - this.cpuLastUsage.user;
    const cpuDiffSystem = cpuSnapshot.system - this.cpuLastUsage.system;
    const cpuElapsedMs = now - this.cpuLastTime;
    const cores = os.cpus().length || 1;
    const cpuPercent =
      cpuElapsedMs > 0
        ? ((cpuDiffUser + cpuDiffSystem) / 1000) / cpuElapsedMs / cores * 100
        : 0;

    this.cpuLastUsage = cpuSnapshot;
    this.cpuLastTime = now;

    return {
      filesScanned: this.state.filesScanned,
      matches: this.state.matches,
      bytesScanned: this.state.bytesScanned,
      queueDepth: this.state.queueDepth,
      workersBusy: this.state.workersBusy,
      elapsedMs,
      filesPerSecond,
      mbPerSecond,
      cpuPercent,
      errors: this.state.errors,
    };
  }
}

export function renderSnapshot(snapshot: TelemetrySnapshot) {
  const parts = [
    `${paint.headline("files")}: ${snapshot.filesScanned.toLocaleString()} (${snapshot.filesPerSecond.toFixed(1)}/s)`,
    `${paint.headline("matches")}: ${snapshot.matches}`,
    `${paint.headline("throughput")}: ${snapshot.mbPerSecond.toFixed(2)} MB/s`,
    `${paint.headline("cpu")}: ${snapshot.cpuPercent.toFixed(1)}%`,
    `${paint.headline("queue")}: ${snapshot.queueDepth}`,
    `${paint.headline("workers")}: ${snapshot.workersBusy}`,
    `${paint.headline("errors")}: ${snapshot.errors}`,
  ];
  writeStdout(`\r${parts.join("  ")}`);
}

export function clearTelemetryLine() {
  writeStdout("\r\u001b[2K");
}
