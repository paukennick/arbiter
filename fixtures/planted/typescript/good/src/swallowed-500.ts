export function handle(res: { status(code: number): { end(): void } }, run: () => void): void {
  try {
    run();
    res.status(200).end();
  } catch (err) {
    console.error("request failed", err);
    res.status(500).end();
  }
}
