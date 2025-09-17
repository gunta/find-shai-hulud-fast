import type { LoadedSignature } from "../signatures/index";
import { matchGlob } from "../utils/glob";
import { sha256File } from "../utils/hash";

interface InitMessage {
  type: "init";
  signatures: LoadedSignature[];
  maxBytes: number;
}

interface ScanMessage {
  type: "scan";
  path: string;
  size: number;
}

interface ShutdownMessage {
  type: "shutdown";
}

interface MatchResult {
  signatureId: string;
  title: string;
  severity: string;
  description: string;
  indicatorType: string;
  indicatorValue: string;
}

interface ScanResultMessage {
  type: "result";
  path: string;
  bytesRead: number;
  matches: MatchResult[];
  error?: string;
}

type IncomingMessage = InitMessage | ScanMessage | ShutdownMessage;

declare const self: Worker;

let signatures: LoadedSignature[] = [];
let maxBytes = 5 * 1024 * 1024;
const textDecoder = new TextDecoder();
const textEncoder = new TextEncoder();

function concatChunks(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const chunk of chunks) {
    total += chunk.byteLength;
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

self.onmessage = async (event: MessageEvent<IncomingMessage>) => {
  const message = event.data;
  switch (message.type) {
    case "init":
      signatures = message.signatures;
      maxBytes = message.maxBytes;
      break;
    case "scan":
      self.postMessage(await handleScan(message));
      break;
    case "shutdown":
      self.close();
      break;
  }
};

async function handleScan(message: ScanMessage): Promise<ScanResultMessage> {
  const { path, size } = message;
  const file = Bun.file(path);
  try {
    if (!(await file.exists())) {
      return { type: "result", path, bytesRead: 0, matches: [], error: "missing" };
    }

    const matches: MatchResult[] = [];

    for (const signature of signatures) {
      const globMatch = signature.globs.some((glob) => matchGlob(path, glob));
      if (globMatch) {
        matches.push({
          signatureId: signature.id,
          title: signature.title,
          severity: signature.severity,
          description: signature.description,
          indicatorType: "glob",
          indicatorValue: signature.globs.find((glob) => matchGlob(path, glob)) ?? "",
        });
        continue;
      }
    }

    let bytesRead = 0;
    let content: string | null = null;
    let lower: string | null = null;

    const needsContent = signatures.some(
      (sig) => sig.regexes.length || sig.strings.length || sig.heuristics.length
    );

    if (needsContent) {
      if (size > maxBytes) {
        // Read only the first chunk up to maxBytes to avoid huge memory usage.
        const stream = file.stream();
        const reader = stream.getReader();
        const chunks: Uint8Array[] = [];
        let accumulated = 0;
        while (accumulated < maxBytes) {
          const { done, value } = await reader.read();
          if (done || !value) break;
          chunks.push(value as Uint8Array);
          accumulated += value.length;
        }
        const buffer = concatChunks(chunks);
        content = textDecoder.decode(buffer);
        bytesRead = buffer.byteLength;
      } else {
        content = await file.text();
        bytesRead = textEncoder.encode(content).byteLength;
      }
      lower = content.toLowerCase();
    }

    let digest: string | null = null;
    const ensureDigest = async () => {
      if (digest) return digest;
      digest = await sha256File(path);
      return digest;
    };

    if (content) {
      for (const signature of signatures) {
        let matched = matches.some((match) => match.signatureId === signature.id);
        if (matched) continue;

        if (signature.strings.length && lower) {
          const indicator = signature.strings.find((needle) => lower!.includes(needle));
          if (indicator) {
            matches.push({
              signatureId: signature.id,
              title: signature.title,
              severity: signature.severity,
              description: signature.description,
              indicatorType: "string",
              indicatorValue: indicator,
            });
            continue;
          }
        }

        if (signature.regexes.length && content) {
          const indicator = signature.regexes.find((regex) => regex.test(content!));
          if (indicator) {
            matches.push({
              signatureId: signature.id,
              title: signature.title,
              severity: signature.severity,
              description: signature.description,
              indicatorType: "regex",
              indicatorValue: indicator.source,
            });
            continue;
          }
        }

        if (signature.heuristics.length && content) {
          if (
            signature.heuristics.some(
              (heuristic) =>
                heuristic.value === "long-line" &&
                content!.split(/\r?\n/).some((line) => line.length > 2000)
            )
          ) {
            matches.push({
              signatureId: signature.id,
              title: signature.title,
              severity: signature.severity,
              description: signature.description,
              indicatorType: "heuristic",
              indicatorValue: "long-line",
            });
            continue;
          }
        }

        if (signature.hashes.length) {
          const hash = await ensureDigest();
          const indicator = signature.hashes.find((h) => h === hash);
          if (indicator) {
            matches.push({
              signatureId: signature.id,
              title: signature.title,
              severity: signature.severity,
              description: signature.description,
              indicatorType: "sha256",
              indicatorValue: indicator,
            });
            continue;
          }
        }
      }
    } else if (signatures.some((sig) => sig.hashes.length)) {
      const hash = await ensureDigest();
      for (const signature of signatures) {
        if (signature.hashes.includes(hash)) {
          matches.push({
            signatureId: signature.id,
            title: signature.title,
            severity: signature.severity,
            description: signature.description,
            indicatorType: "sha256",
            indicatorValue: hash,
          });
        }
      }
    }

    return { type: "result", path, bytesRead, matches };
  } catch (error) {
    return {
      type: "result",
      path,
      bytesRead: 0,
      matches: [],
      error: error instanceof Error ? error.message : String(error),
    };
  }
}
