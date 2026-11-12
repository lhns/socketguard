import {
  toDaemonError, type App, type CredentialKind, type NewCredential, type ParsedCredential,
  type Peer, type PeerGroup, type PortRange, type PortRef, type Scope, type PortGroup, type Subject, type Tag, type Target,
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

/** Same port (or both All ports). */

export const ALL_SCOPE: Scope = { kind: "all" };

/** The scope of one port, or All ports for null. */
export const scopeOfPort = (p: PortRef | null): Scope =>
  p === null ? ALL_SCOPE : { kind: "port", port: p.port, proto: p.proto };

/** The port of a port scope; null for All ports and for a port group. */
export const portOfScope = (s: Scope): PortRef | null =>
  s.kind === "port" ? { port: s.port, proto: s.proto } : null;

/** Structural equality of scopes. */
export const sameScope = (a: Scope, b: Scope) =>
  a.kind === "all" ? b.kind === "all"
  : a.kind === "port" ? b.kind === "port" && a.port === b.port && a.proto === b.proto
  : b.kind === "group" && a.id === b.id;

/** "All ports", "80/tcp" or the port group's name (the id when the group is not in `groups`). */
export const scopeLabel = (s: Scope, groups: PortGroup[] = []): string =>
  s.kind === "all" ? "All ports"
  : s.kind === "port" ? portLabel(s)
  : groups.find((g) => g.id === s.id)?.label ?? s.id;

/** "53/udp" or "50000-51000/tcp". */
export const rangeLabel = (r: PortRange) => (r.start === r.end ? `${r.start}/${r.proto}` : `${r.start}-${r.end}/${r.proto}`);

/** Parse "80/tcp", "50000-51000/tcp"; an error text for anything else. */
export function parseRange(text: string): PortRange | string {
  const m = /^(\d{1,5})(?:\s*-\s*(\d{1,5}))?\s*\/\s*(tcp|udp)$/i.exec(text.trim());
  if (!m) return `"${text.trim()}" is not a port: write 80/tcp, 53/udp or 50000-51000/tcp.`;
  const start = Number(m[1]);
  const end = m[2] === undefined ? start : Number(m[2]);
  if (start < 1 || end > 65535) return "Ports go from 1 to 65535.";
  if (end < start) return "A range starts at its lower port.";
  return { start, end, proto: m[3].toLowerCase() as PortRange["proto"] };
}

/** Add a range to a list, kept sorted; a repeated range stays once. */
export function withRange(ranges: PortRange[], add: PortRange): PortRange[] {
  if (ranges.some((r) => r.start === add.start && r.end === add.end && r.proto === add.proto)) return ranges;
  return [...ranges, add].sort((a, b) => a.proto.localeCompare(b.proto) || a.start - b.start || a.end - b.end);
}

/** Key for grouping by scope. */
export const scopeKey = (s: Scope) => (s.kind === "all" ? "*" : s.kind === "port" ? portLabel(s) : `group:${s.id}`);

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

export function targetLabel(
  t: Target,
  apps: App[] = [],
  tags: Tag[] = [],
  reservations: { id: string; label: string }[] = [],
): string {
  if (t.kind === "app") return apps.find((a) => a.id === t.id)?.name ?? `app ${t.id.slice(0, 8)}`;
  if (t.kind === "reservation") {
    return `reserved ${reservations.find((r) => r.id === t.id)?.label ?? t.id.slice(0, 8)}`;
  }
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

/** Save text as a file through the browser's download. */
export function saveTextFile(text: string, name: string, type = "application/json") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}
