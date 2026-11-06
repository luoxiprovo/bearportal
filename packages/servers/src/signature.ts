function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, item]) => [key, sortValue(item)]),
    );
  }
  return value;
}

export function heartbeatMessage(body: {
  serverId: string;
  authEpoch: number;
  observedAt: string;
  readiness: Record<string, unknown>;
}): string {
  return JSON.stringify(sortValue(body));
}
