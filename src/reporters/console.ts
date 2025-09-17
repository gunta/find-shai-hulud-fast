import { paint } from "../utils/logger";
import type { Detection, ScanSummary } from "../scanner/index";
import { clearTelemetryLine } from "../telemetry";
import { writeStdout, readLine, isInteractiveStdout } from "../utils/io";

function severityColor(severity: string): (text: string) => string {
  switch (severity) {
    case "critical":
      return paint.error;
    case "high":
      return paint.warn;
    case "medium":
      return paint.headline;
    default:
      return paint.info;
  }
}

export function printDetections(detections: Detection[]) {
  if (!detections.length) return;
  clearTelemetryLine();
  writeStdout(`\n${paint.error("Detections found:")}\n`);
  detections.forEach((detection, index) => {
    const colorize = severityColor(detection.severity);
    writeStdout(
      `${paint.bold(`#${index + 1}`)} ${colorize(`${detection.severity.toUpperCase()} ${detection.title}`)}\n`
    );
    writeStdout(`  ${paint.dim("Signature")}: ${detection.signatureId}\n`);
    writeStdout(`  ${paint.dim("Path")}: ${detection.path}\n`);
    writeStdout(
      `  ${paint.dim("Indicator")}: ${detection.indicatorType} → ${detection.indicatorValue}\n`
    );
    writeStdout(`  ${paint.dim("Details")}: ${detection.description}\n\n`);
  });
}

export function printSummary(summary: ScanSummary) {
  clearTelemetryLine();
  const seconds = summary.durationMs / 1000;
  const throughput =
    seconds > 0 ? `${(summary.bytesScanned / 1024 / 1024 / seconds).toFixed(2)} MB/s` : "n/a";
  const profileSummary = summary.signatureSummary;
  const profileId = profileSummary.profileId ?? profileSummary.manifestId ?? "custom";
  const profileLabel = profileSummary.title
    ? `${profileId} – ${profileSummary.title}`
    : profileId;
  writeStdout(`${paint.bold("Scan Summary")}:\n`);
  writeStdout(`  Profile: ${profileLabel}\n`);
  if (profileSummary.updated) {
    writeStdout(`  Profile updated: ${profileSummary.updated}\n`);
  }
  writeStdout(`  Files scanned: ${summary.scannedFiles}\n`);
  writeStdout(`  Bytes read: ${(summary.bytesScanned / (1024 * 1024)).toFixed(2)} MB\n`);
  writeStdout(`  Duration: ${seconds.toFixed(2)} s\n`);
  writeStdout(`  Throughput: ${throughput}\n`);
  writeStdout(`  Detections: ${summary.detections.length}\n`);
  writeStdout(`  Errors: ${summary.errors.length}\n`);
  if (profileSummary.sources?.length) {
    writeStdout(`  Sources: ${profileSummary.sources.join(", ")}\n`);
  }
}

export async function promptRemediation(detections: Detection[]) {
  if (!detections.length) return;
  writeStdout(
    `\n${paint.warn(
      "Remediation Guidance"
    )}: Review and remove the malicious packages. Suggested steps:\n`
  );
  writeStdout("  1. Remove the compromised package (npm uninstall <name>).\n");
  writeStdout(
    "  2. Delete affected node_modules and lockfiles, reinstall from trusted sources.\n"
  );
  writeStdout("  3. Rotate credentials if exposed, audit system activity logs.\n");
  writeStdout(
    "  4. Report internally and fetch latest signature updates once available.\n\n"
  );

  if (!isInteractiveStdout()) {
    return;
  }

  const answer = await readLine(`${paint.bold("Mark detections as acknowledged? (y/N)")} `);
  if (answer.trim().toLowerCase() === "y") {
    writeStdout(`${paint.success("Acknowledged.")}\n`);
  } else {
    writeStdout(`${paint.warn("Detections remain unacknowledged.")}\n`);
  }
}
