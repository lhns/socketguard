import {
  toDaemonError, type CredentialKind, type NewCredential, type ParsedCredential, type PeerGroup, type Peer, type Subject,
} from "./api";
import { CREDENTIAL_EXAMPLES } from "./generated/credentialExamples";

export const errorText = (e: unknown): string => toDaemonError(e).message;

/** The credentials to send for pasted text already classified by the daemon's parser, or the
 * first error. */
export function credentialsFromParsed(
  parsed: ParsedCredential[],
): { credentials: NewCredential[] } | { error: string } {
  if (parsed.length === 0) return { error: "Enter a key, address or IP." };
  const bad = parsed.find((p) => p.error !== null || p.kind === null || p.normalized === null);
  if (bad) return { error: `${bad.input}: ${bad.error ?? "not recognised"}` };
  return { credentials: parsed.map((p) => ({ kind: p.kind as CredentialKind, value: p.normalized as string, label: null })) };
}

/** Placeholder for credential inputs, built from the examples the daemon's tests parse. */
export const CREDENTIAL_PLACEHOLDER = `e.g. ${CREDENTIAL_EXAMPLES.filter((e) => e.kind === "ygg_addr" || e.kind === "ip")
  .map((e) => e.value)
  .join(", ")}`;

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
