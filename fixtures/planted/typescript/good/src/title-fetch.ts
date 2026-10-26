import dns from "node:dns/promises";
import https from "node:https";

async function assertPublicHost(url: URL): Promise<string> {
  const addrs = await dns.lookup(url.hostname, { all: true });
  if (addrs.some((a) => a.address.startsWith("10.") || a.address === "127.0.0.1")) {
    throw new Error("blocked");
  }
  return addrs[0].address;
}

export async function fetchTitle(raw: string): Promise<void> {
  const url = new URL(raw);
  const ip = await assertPublicHost(url);
  https.get(url, { timeout: 5000, lookup: (_h, _o, cb) => cb(null, ip, 4) }).end();
}
