import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import { Logger } from "./utils/logger";

export interface CloneOptions {
  url: string;
  branch?: string;
  keepTemp?: boolean;
  logger: Logger;
}

export interface CloneResult {
  path: string;
  cleanup: () => Promise<void>;
}

const textDecoder = new TextDecoder();

export async function cloneRepository(options: CloneOptions): Promise<CloneResult> {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "shai-scan-"));
  options.logger.info(`Cloning ${options.url} to ${tmpDir}`);

  const clone = Bun.spawnSync(["git", "clone", options.url, tmpDir, "--depth", "1"], {
    stdout: "pipe",
    stderr: "pipe",
  });
  const cloneStdout = clone.stdout ? textDecoder.decode(clone.stdout) : "";
  const cloneStderr = clone.stderr ? textDecoder.decode(clone.stderr) : "";
  if (clone.exitCode !== 0) {
    throw new Error(`git clone failed: ${cloneStderr || cloneStdout}`);
  }

  if (options.branch) {
    const checkout = Bun.spawnSync(["git", "checkout", options.branch], {
      cwd: tmpDir,
      stdout: "pipe",
      stderr: "pipe",
    });
    const checkoutStdout = checkout.stdout ? textDecoder.decode(checkout.stdout) : "";
    const checkoutStderr = checkout.stderr ? textDecoder.decode(checkout.stderr) : "";
    if (checkout.exitCode !== 0) {
      throw new Error(`git checkout failed: ${checkoutStderr || checkoutStdout}`);
    }
  }

  async function cleanup() {
    if (options.keepTemp) {
      options.logger.info(`Keeping cloned repository at ${tmpDir}`);
      return;
    }
    options.logger.info(`Removing temporary clone ${tmpDir}`);
    await fs.rm(tmpDir, { recursive: true, force: true });
  }

  return { path: tmpDir, cleanup };
}
