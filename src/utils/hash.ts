const textEncoder = new TextEncoder();

function toHex(buffer: ArrayBuffer | ArrayBufferView): string {
  let view: Uint8Array;
  if (buffer instanceof Uint8Array) {
    view = buffer;
  } else if (ArrayBuffer.isView(buffer)) {
    view = new Uint8Array(buffer.buffer);
  } else {
    view = new Uint8Array(buffer);
  }
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
  const buffer = (await file.arrayBuffer()) as unknown as ArrayBuffer;
  hasher.update(new Uint8Array(buffer));
  const digest = hasher.digest();
  const digestBytes =
    digest instanceof Uint8Array ? digest : new Uint8Array(digest as unknown as ArrayBuffer);
  return toHex(digestBytes);
}
