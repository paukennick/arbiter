import dns from "node:dns/promises";

async function assertPublicHost(url: URL): Promise<void> {
  const addrs = await dns.lookup(url.hostname, { all: true });
  if (addrs.some((a) => a.address.startsWith("10.") || a.address === "127.0.0.1")) {
    throw new Error("blocked");
  }
}

export async function fetchTitle(raw: string): Promise<string> {
  const url = new URL(raw);
  await assertPublicHost(url); // expect: arbiter/typescript.ssrf-check-then-connect
  const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
  return res.text();
}
