import {
  toDaemonError, type App, type CredentialKind, type NewCredential, type ParsedCredential,
  type Peer, type PeerGroup, type PortRef, type Subject, type Tag, type Target,
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

/** Same port (or both "all ports"). */
export const samePort = (a: PortRef | null, b: PortRef | null) =>
  a === null || b === null ? a === b : a.port === b.port && a.proto === b.proto;

/** A batch error names its operation: "operation 2: ...". Returns the zero-based index and the
 * message without that prefix; index null when the error is not about one operation. */
export function splitOperationError(message: string): { index: number | null; text: string } {
  const m = /operation (\d+)\)?:?\s*(.*)$/s.exec(message);
  if (!m) return { index: null, text: message };
  const before = message.slice(0, m.index).replace(/\s*\($/, "").trim();
  return { index: Number(m[1]), text: m[2] || before || message };
}

/** Which form field a daemon error belongs to, from its code and message. */
export type ErrorField = "label" | "credentials" | "port" | "patterns" | "other";
export function errorField(e: unknown): ErrorField {
  const err = toDaemonError(e);
  const m = err.message.toLowerCase();
  if (err.code === "conflict" && m.includes("label")) return "label";
  if (m.includes("label")) return "label";
  if (m.includes("credential") || m.includes("key") || m.includes("address")) return "credentials";
  if (m.includes("port")) return "port";
  if (m.includes("pattern") || m.includes("glob")) return "patterns";
  return "other";
}

export function targetLabel(t: Target, apps: App[] = [], tags: Tag[] = []): string {
  if (t.kind === "app") return apps.find((a) => a.id === t.id)?.name ?? `app ${t.id.slice(0, 8)}`;
  return `tag ${tags.find((x) => x.id === t.id)?.label ?? t.id.slice(0, 8)}`;
}

/** Wording of an open grant: "Anyone", or everyone on one network (a segment). */
export function openWording(networkNames: string[]): string {
  return networkNames.length === 0 ? "Anyone" : `Everyone on ${networkNames.join(", ")}`;
}

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
