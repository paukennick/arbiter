import path from "node:path";

export function resolveImage(input: string): string {
  const resolved = path.resolve(input);
  const root = process.env.IMAGE_ROOT;
  if (root) { // expect: arbiter/typescript.path-confinement-optional
    const rel = path.relative(path.resolve(root), resolved);
    if (rel.startsWith("..") || path.isAbsolute(rel)) {
      throw new Error("outside root");
    }
  }
  return resolved;
}
