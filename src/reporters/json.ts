import type { ScanSummary } from "../scanner/index";
import { writeStdout } from "../utils/io";

export function emitJson(summary: ScanSummary) {
  const payload = {
    scannedFiles: summary.scannedFiles,
    bytesScanned: summary.bytesScanned,
    durationMs: summary.durationMs,
    detections: summary.detections,
    errors: summary.errors,
    signatureSummary: summary.signatureSummary,
    generatedAt: new Date().toISOString(),
  };
  writeStdout(`${JSON.stringify(payload, null, 2)}\n`);
}
