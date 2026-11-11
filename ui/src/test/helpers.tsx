import type { ReactElement } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import { mockIPC } from "@tauri-apps/api/mocks";
import { ToastProvider } from "../components/Toast";
import { createQueryClient } from "../queries";
import { NavContext, type Focus, type Page } from "../nav";
import type {
  Address, AppDetail, App, BindingTarget, ChangesResponse, ReservationView, Enforcement, GrantView, Network, ParsedCredential, Peer, PeerGroup, Settings,
  StatusResponse, Tag, NetworkSetup, SetupState,
} from "../api";

export const networks: Network[] = [
  { id: "n-local", kind: "local", name: "Local", interface: "lo", grants_apply: false, status: { state: "up" } },
  { id: "n-ygg", kind: "yggdrasil", name: "Yggdrasil", interface: "ygg0", grants_apply: true, status: { state: "up" } },
  { id: "n-lan", kind: "lan", name: "LAN", interface: "eth0", grants_apply: true, status: { state: "up" } },
];

const state = (state: SetupState["state"], over: Partial<SetupState> = {}): SetupState => ({ state, found: {}, exposed: false, ...over });

/** What `network_setup` answers by default: one LAN interface, nothing else installed. */
export const networkSetup: NetworkSetup = {
  lan: [
    { interface: "Ethernet 2", description: "Red Hat VirtIO Ethernet Adapter", has_ipv6_prefix: true, is_default_route: true, already_added: false },
    { interface: "Ethernet 3", has_ipv6_prefix: false, is_default_route: false, already_added: false },
  ],
  yggdrasil: state("not_installed", {
    missing: "Yggdrasil is not installed.",
    download_link: "https://yggdrasil-network.github.io/installation.html",
  }),
  tor: state("not_installed", {
    missing: "Tor is not installed. Windows has no package for it; download the Tor Expert Bundle, then come back here.",
    download_link: "https://www.torproject.org/download/tor/",
  }),
  local: state("ready"),
  config_path: "C:\\ProgramData\\SocketGuard\\socketguard.json",
};
export const setupState = state;

export const app1: App = {
  id: "a1", name: "nginx", process_name: "nginx", exe_path: "/usr/sbin/nginx", interpreter_arg: null, identity_note: null,
  reviewed: false, system: false, first_seen: "2026-01-01T00:00:00Z", last_seen: "2026-01-01T00:00:00Z",
  ports: [{ port: 8080, proto: "tcp", listening: true, last_seen: "2026-01-01T00:00:00Z", family: "dual" }],
  addresses: [
    { id: "ad1", app_id: "a1", network_id: "n-ygg", scope: { kind: "all" }, locator: { kind: "ipv6", addr: "302::1" }, created_at: "2026-01-01T00:00:00Z", reservation_id: null, up: true, excluded: [], notes: [] },
  ],
};

export const appDetail: AppDetail = { ...app1, grants: [], access: [], tags: [], counters: [], port_groups: [] };

export const alice: Peer = {
  id: "p1", label: "alice", groups: [], created_at: "2026-01-01T00:00:00Z",
  credentials: [{ id: "c1", kind: "ygg_key", value: "a".repeat(64), label: null }],
};

export const groups: PeerGroup[] = [];
export const noTags: Tag[] = [];

/** A change's answer as the Tauri commands return it: the value and the 202 notice (or none). */
export const saved = <T,>(value: T, enforcement: Enforcement | null = null) => ({ value, enforcement });
export const settings: Settings = { protect_host_interfaces: [] };
export const status: StatusResponse = {
  version: "0.1.0", networks, protect_host_interfaces: [], disabled: false, unadopted: false,
  counts: { apps: 1, pending_apps: 1, addresses: 1, peers: 1, groups: 0, grants: 0 },
};

export const grantView = (over: Partial<GrantView> = {}): GrantView => ({
  id: "g1", target: { kind: "app", id: "a1" }, scope: { kind: "all" }, network_id: null, subject: { kind: "peer", id: "p1" },
  created_at: "2026-01-01T00:00:00Z", reach: [{ network_id: "n-ygg", reach: "verified" }], ...over,
});

const T0 = "2026-01-01T00:00:00Z";

/** An app with the given ports (listening, dual stack) and one address on Yggdrasil. */
export const mkApp = (id: string, name: string, ports: number[] = [8080], over: Partial<App> = {}): App => ({
  id, name, process_name: name, exe_path: `/usr/bin/${name}`, interpreter_arg: null, identity_note: null, reviewed: true,
  system: false, first_seen: T0, last_seen: T0,
  ports: ports.map((port) => ({ port, proto: "tcp" as const, listening: true, last_seen: T0, family: "dual" as const })),
  addresses: [{ id: `${id}-y`, app_id: id, network_id: "n-ygg", scope: { kind: "all" }, locator: { kind: "ipv6", addr: `302::${id.length}` }, created_at: T0, reservation_id: null, up: true, excluded: [], notes: [] }],
  ...over,
});

export const mkTag = (id: string, label: string, appIds: string[] = [], patterns: string[] = []): Tag => ({
  id, label, patterns, excluded: [], created_at: T0, members: appIds.map((app_id) => ({ app_id, scope: { kind: "all" as const } })),
});

export const mkPeer = (id: string, label: string, over: Partial<Peer> = {}): Peer => ({
  id, label, groups: [], created_at: T0, credentials: [{ id: `c-${id}`, kind: "ygg_key", value: id.repeat(64).slice(0, 64), label: null }], ...over,
});

export const mkAddress = (id: string, network_id: string, addr: string, over: Partial<Address> = {}): Address => ({
  id, network_id, locator: { kind: "ipv6", addr }, created_at: T0, app_id: null, scope: { kind: "all" }, reservation_id: null, up: true, excluded: [], notes: [], ...over,
});

/** A reservation with one address on Yggdrasil and the given bindings. */
export const mkReservation = (id: string, label: string, targets: BindingTarget[] = [], over: Partial<ReservationView> = {}): ReservationView => ({
  id, label, created_at: T0, conflicts: [], grants: [],
  bindings: targets.map((target, i) => ({ id: `${id}-b${i}`, reservation_id: id, target })),
  addresses: [mkAddress(`${id}-ad`, "n-ygg", "302:ffff::1", { reservation_id: id })],
  ...over,
});

export const mkGroup = (id: string, label: string, members: string[] = []): PeerGroup => ({ id, label, members, created_at: T0 });

export const detail = (app: App, over: Partial<AppDetail> = {}): AppDetail => ({ ...app, grants: [], access: [], tags: [], counters: [], port_groups: [], ...over });

/** A working Storage: some Node versions shadow jsdom's with a broken experimental one. */
export function memoryStorage() {
  const m = new Map<string, string>();
  return {
    getItem: (k: string) => m.get(k) ?? null,
    setItem: (k: string, v: string) => void m.set(k, String(v)),
    removeItem: (k: string) => void m.delete(k),
    clear: () => m.clear(),
  };
}

/** What `changes` answers: the diff and whether it lets somebody in. */
export const batch = (req: { dry_run: boolean }, changes_reach = false, changes: ChangesResponse["changes"] = []) =>
  saved<ChangesResponse>({ dry_run: req.dry_run, refs: {}, changes, changes_reach });

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
    list_tags: () => noTags,
    list_port_groups: () => [],
    share_app: () => ({ tor: [] }),
    list_networks: () => networks,
    network_setup: () => networkSetup,
    exposure: () => ({ networks: [] }),
    list_reservations: () => [],
    list_addresses: () => [],
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

export function renderWithProviders(ui: ReactElement, go: (page: Page, focus?: Focus) => void = () => {}) {
  return render(
    <QueryClientProvider client={createQueryClient()}>
      <NavContext.Provider value={{ go }}>
        <ToastProvider>{ui}</ToastProvider>
      </NavContext.Provider>
    </QueryClientProvider>,
  );
}
