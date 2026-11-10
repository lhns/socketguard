import type { ReactElement } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import { mockIPC } from "@tauri-apps/api/mocks";
import { ToastProvider } from "../components/Toast";
import { createQueryClient } from "../queries";
import type {
  AppDetail, App, GrantView, Network, ParsedCredential, Peer, PeerGroup, Settings, StatusResponse,
} from "../api";

export const networks: Network[] = [
  { id: "n-local", kind: "local", name: "Local", interface: "lo", grants_apply: false, status: { state: "up" } },
  { id: "n-ygg", kind: "yggdrasil", name: "Yggdrasil", interface: "ygg0", grants_apply: true, status: { state: "up" } },
  { id: "n-lan", kind: "lan", name: "LAN", interface: "eth0", grants_apply: true, status: { state: "up" } },
];

export const app1: App = {
  id: "a1", name: "nginx", process_name: "nginx", exe_path: "/usr/sbin/nginx", interpreter_arg: null, identity_note: null,
  reviewed: false, first_seen: "2026-01-01T00:00:00Z", last_seen: "2026-01-01T00:00:00Z",
  ports: [{ port: 8080, proto: "tcp", listening: true, last_seen: "2026-01-01T00:00:00Z", family: "dual" }],
  addresses: [
    { id: "ad1", app_id: "a1", network_id: "n-ygg", ports: "all", locator: { kind: "ipv6", addr: "302::1" }, created_at: "2026-01-01T00:00:00Z" },
  ],
};

export const appDetail: AppDetail = { ...app1, grants: [], counters: [] };

export const alice: Peer = {
  id: "p1", label: "alice", groups: [], created_at: "2026-01-01T00:00:00Z",
  credentials: [{ id: "c1", kind: "ygg_key", value: "a".repeat(64), label: null }],
};

export const groups: PeerGroup[] = [];
export const settings: Settings = { address_mode: "per_app", protect_host_interfaces: [] };
export const status: StatusResponse = {
  version: "0.1.0", networks, protect_host_interfaces: [], disabled: false, unadopted: false,
  counts: { apps: 1, pending_apps: 1, addresses: 1, peers: 1, groups: 0, grants: 0 },
};

export const grantView = (over: Partial<GrantView> = {}): GrantView => ({
  id: "g1", app_id: "a1", port: null, network_id: null, subject: { kind: "peer", id: "p1" },
  created_at: "2026-01-01T00:00:00Z", reach: [{ network_id: "n-ygg", reach: "verified" }], ...over,
});

/** Stand-in for the daemon's parser: 64 hex characters are a key, anything with a colon or dot
 * an IP, the rest an error. The real classification is tested in the core crate. */
export function fakeParse({ text }: { text?: unknown }): ParsedCredential[] {
  return String(text ?? "")
    .split(/[\s,]+/)
    .filter(Boolean)
    .map((input) => {
      const kind = /^[0-9a-f]{64}$/i.test(input) ? "ygg_key" : /[:.]/.test(input) ? "ip" : null;
      return kind
        ? { input, kind, normalized: input, reach: [], error: null }
        : { input, kind: null, normalized: null, reach: [], error: `cannot tell what "${input}" is` };
    });
}

type Args = Record<string, unknown>;
export type Handlers = Record<string, (args: Args) => unknown>;
export interface Call { cmd: string; args: Args }

/** Mock the Tauri commands with sensible defaults; `handlers` override per command. */
export function mockDaemon(handlers: Handlers = {}) {
  const calls: Call[] = [];
  const defaults: Handlers = {
    status: () => status,
    list_apps: () => [app1],
    get_app: () => appDetail,
    list_peers: () => [alice],
    parse_credentials: (a) => fakeParse(a),
    list_groups: () => groups,
    list_grants: () => [],
    list_networks: () => networks,
    get_settings: () => settings,
    activity: () => [],
    subscribe_events: () => undefined,
  };
  mockIPC(
    (cmd, args) => {
      if (cmd.startsWith("plugin:")) return undefined;
      calls.push({ cmd, args: (args ?? {}) as Args });
      const h = handlers[cmd] ?? defaults[cmd];
      if (!h) throw { code: "internal", message: `unmocked command ${cmd}` };
      return h((args ?? {}) as Args);
    },
    { shouldMockEvents: true },
  );
  return { calls, count: (cmd: string) => calls.filter((c) => c.cmd === cmd).length, last: (cmd: string) => { const m = calls.filter((c) => c.cmd === cmd); return m[m.length - 1]; } };
}

export function renderWithProviders(ui: ReactElement) {
  return render(
    <QueryClientProvider client={createQueryClient()}>
      <ToastProvider>{ui}</ToastProvider>
    </QueryClientProvider>,
  );
}
