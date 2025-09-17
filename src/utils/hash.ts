const textEncoder = new TextEncoder();

function toHex(buffer: ArrayBuffer): string {
  const view = new Uint8Array(buffer);
  let result = "";
  for (let i = 0; i < view.length; i += 1) {
    result += view[i].toString(16).padStart(2, "0");
  }
  return result;
}

export async function sha256File(path: string): Promise<string> {
  const file = Bun.file(path);
  if (!(await file.exists())) {
    throw new Error(`File not found: ${path}`);
  }
  const hasher = new Bun.CryptoHasher("sha256");
  const stream = file.stream();
  for await (const chunk of stream) {
    if (chunk instanceof Uint8Array || ArrayBuffer.isView(chunk)) {
      hasher.update(chunk as Uint8Array);
    } else if (chunk instanceof ArrayBuffer) {
      hasher.update(new Uint8Array(chunk));
    } else if (typeof chunk === "string") {
      hasher.update(textEncoder.encode(chunk));
    }
  }
  return toHex(hasher.digest());
}
