import { Resolver } from "node:dns/promises";

/** Read the public NS set. A lookup failure or a five-second timeout returns an empty list. */
export async function lookupNameservers(domain: string): Promise<string[]> {
  const resolver = new Resolver();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const pending = resolver.resolveNs(domain).then(
    (names) => names,
    () => [] as string[],
  );
  try {
    const names = await Promise.race([
      pending,
      new Promise<string[]>((resolve) => {
        timer = setTimeout(() => {
          resolver.cancel();
          resolve([]);
        }, 5000);
      }),
    ]);
    return names.map((name) => name.trim().toLowerCase().replace(/\.$/, "")).filter((name) => name.length > 0).sort();
  } finally {
    if (timer) clearTimeout(timer);
  }
}
