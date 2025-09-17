import path from "node:path";

const jsonCache = new Map<string, Promise<unknown>>();

export async function readJsonFile<T>(filePath: string): Promise<T> {
  const resolved = path.resolve(filePath);
  let cached = jsonCache.get(resolved);
  if (!cached) {
    cached = Bun.file(resolved).json();
    jsonCache.set(resolved, cached);
  }
  return (await cached) as T;
}

export function clearJsonCache(): void {
  jsonCache.clear();
}
