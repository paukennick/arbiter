import path from "node:path";

const ROOT = path.resolve(process.env.IMAGE_ROOT ?? "/srv/images");

export function resolveImage(input: string): string {
  const resolved = path.resolve(ROOT, input);
  const rel = path.relative(ROOT, resolved);
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new Error("outside root");
  }
  return resolved;
}
