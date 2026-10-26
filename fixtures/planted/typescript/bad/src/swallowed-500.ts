export function handle(res: { status(code: number): { end(): void } }, run: () => void): void {
  try {
    run();
    res.status(200).end();
  } catch { // expect: arbiter/typescript.swallowed-catch-to-500
    res.status(500).end();
  }
}
