import { toDaemonError, type CredentialKind, type PeerGroup, type Peer, type Subject } from "./api";

export const errorText = (e: unknown): string => toDaemonError(e).message;

/** 64 hex characters are a Yggdrasil key; 52 base32 characters (or a
 * `descriptor:x25519:` line) are a Tor client key; anything else is sent as an IP or
 * CIDR. The daemon validates and reclassifies (a 200::/7 address becomes `ygg_addr`). */
export function guessCredentialKind(value: string): CredentialKind {
  const v = value.trim();
  if (/^[0-9a-fA-F]{64}$/.test(v)) return "ygg_key";
  if (/^([a-z0-9]+:){0,2}[A-Za-z2-7]{52}$/.test(v) && (!v.includes(":") || /^descriptor:x25519:/i.test(v))) {
    return "tor_client_key";
  }
  return "ip";
}

export function subjectLabel(s: Subject, peers: Peer[] = [], groups: PeerGroup[] = []): string {
  switch (s.kind) {
    case "anyone":
      return "Anyone";
    case "peer":
      return peers.find((p) => p.id === s.id)?.label ?? `peer ${s.id.slice(0, 8)}`;
    case "group":
      return `group ${groups.find((g) => g.id === s.id)?.label ?? s.id.slice(0, 8)}`;
  }
}

export const portLabel = (p: { port: number; proto: string }) => `${p.port}/${p.proto}`;

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

export function formatTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}
