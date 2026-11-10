// Development only (loaded from main.tsx behind `import.meta.env.DEV` and `?mock`): fake daemon
// data behind the Tauri commands, so the real frontend can be looked at in a plain browser.
// It is not part of the production bundle.
import { mockIPC } from "@tauri-apps/api/mocks";
import type {
  App, AppDetail, BatchChange, ChangeOp, EffectiveAccess, GrantReach, GrantView, Network, Peer, PeerGroup, Subject, Tag,
} from "../api";

const T0 = "2026-01-01T00:00:00Z";
const networks: Network[] = [
  { id: "n-local", kind: "local", name: "Local", interface: "lo", grants_apply: false, status: { state: "up" } },
  { id: "n-ygg", kind: "yggdrasil", name: "Yggdrasil", interface: "ygg0", grants_apply: true, status: { state: "up" } },
  { id: "n-lan", kind: "lan", name: "LAN", interface: "eth0", grants_apply: true, status: { state: "up" } },
];

let seq = 100;
const uid = (p: string) => `${p}${seq++}`;

const own: [string, string, [number, "tcp" | "udp"][]][] = [
  ["nginx", "/usr/sbin/nginx", [[80, "tcp"], [443, "tcp"]]],
  ["postgres", "/usr/lib/postgresql/16/bin/postgres", [[5432, "tcp"]]],
  ["redis-server", "/usr/bin/redis-server", [[6379, "tcp"]]],
  ["sshd", "/usr/sbin/sshd", [[22, "tcp"]]],
  ["grafana", "/usr/share/grafana/bin/grafana", [[3000, "tcp"], [3001, "tcp"]]],
  ["api-server", "/opt/api/bin/api-server", [[8080, "tcp"], [8081, "tcp"], [9229, "tcp"]]],
  ["minio", "/usr/local/bin/minio", [[9000, "tcp"], [9001, "tcp"]]],
  ["prometheus", "/usr/local/bin/prometheus", [[9090, "tcp"]]],
];
const sys = [
  "svchost (RpcSs)", "svchost (Dnscache)", "svchost (LanmanServer)", "svchost (Schedule)", "svchost (W32Time)", "lsass", "spoolsv",
  "wininit", "services", "System", "dns", "ntpd", "systemd-resolved", "avahi-daemon", "cupsd", "chronyd", "NetworkManager", "dhclient",
  "rpcbind", "smbd", "nmbd", "mDNSResponder", "SearchIndexer", "wsmprovhost", "MsMpEng", "OneApp", "dasHost", "sshd (system)", "WUDFHost", "Dhcp",
];

let apps: App[] = [];
own.forEach(([name, exe, ports], i) => {
  const id = `a${i + 1}`;
  apps.push({
    id, name, process_name: name, exe_path: exe, interpreter_arg: null, identity_note: null, reviewed: i % 3 !== 2, system: false,
    first_seen: T0, last_seen: T0,
    ports: ports.map(([port, proto]) => ({ port, proto, listening: true, last_seen: T0, family: i % 2 ? "dual" : "v6" })),
    addresses: [
      { id: `${id}-y`, app_id: id, network_id: "n-ygg", ports: "all", locator: { kind: "ipv6", addr: `302:a${i}::1` }, created_at: T0 },
      { id: `${id}-l`, app_id: id, network_id: "n-lan", ports: "all", locator: { kind: "ipv6", addr: `fd00:1::${i + 10}` }, created_at: T0 },
    ],
  });
});
apps[0].addresses.push({ id: "a1-y2", app_id: "a1", network_id: "n-ygg", ports: { only: [{ port: 443, proto: "tcp" }] }, locator: { kind: "ipv6", addr: "302:a0::2" }, created_at: T0 });
sys.forEach((name, i) => {
  const id = `s${i + 1}`;
  apps.push({
    id, name, process_name: name, exe_path: null, interpreter_arg: null, identity_note: null, reviewed: true, system: true,
    first_seen: T0, last_seen: T0,
    ports: [{ port: 100 + i, proto: "tcp", listening: true, last_seen: T0, family: "v6" }],
    addresses: [{ id: `${id}-y`, app_id: id, network_id: "n-ygg", ports: "all", locator: { kind: "ipv6", addr: `302:b${i}::1` }, created_at: T0 }],
  });
});

const key = (c: string) => c.repeat(64);
let peers: Peer[] = [
  { id: "p1", label: "alice", groups: ["g1"], created_at: T0, credentials: [{ id: "c1", kind: "ygg_key", value: key("a"), label: null }] },
  { id: "p2", label: "bob", groups: ["g1"], created_at: T0, credentials: [{ id: "c2", kind: "ygg_key", value: key("b"), label: null }] },
  { id: "p3", label: "carol", groups: ["g2"], created_at: T0, credentials: [{ id: "c3", kind: "ygg_key", value: key("c"), label: null }] },
  { id: "p4", label: "ci-runner", groups: ["g2"], created_at: T0, credentials: [{ id: "c4", kind: "ip", value: "fd00:1::99", label: null }] },
  { id: "p5", label: "laptop", groups: [], created_at: T0, credentials: [{ id: "c5", kind: "ygg_addr", value: "200:1234::1", label: null }, { id: "c6", kind: "ip", value: "192.168.1.20", label: null }] },
  { id: "p6", label: "phone", groups: [], created_at: T0, credentials: [] },
];
let groups: PeerGroup[] = [
  { id: "g1", label: "team", members: ["p1", "p2"], created_at: T0 },
  { id: "g2", label: "ops", members: ["p3", "p4"], created_at: T0 },
];
let tags: Tag[] = [
  { id: "t1", label: "web", patterns: ["nginx*"], excluded: [], created_at: T0, members: [{ app_id: "a1", port: null }, { app_id: "a5", port: null }, { app_id: "a6", port: null }] },
  { id: "t2", label: "data", patterns: [], excluded: [], created_at: T0, members: [{ app_id: "a2", port: null }, { app_id: "a3", port: null }] },
  { id: "t3", label: "admin", patterns: [], excluded: [], created_at: T0, members: [{ app_id: "a4", port: null }] },
  { id: "t4", label: "monitoring", patterns: ["prom*", "grafana"], excluded: [], created_at: T0, members: [{ app_id: "a8", port: null }, { app_id: "a5", port: { port: 3000, proto: "tcp" } }] },
];
interface G { id: string; target: GrantView["target"]; port: GrantView["port"]; network_id: string | null; subject: Subject }
let grants: G[] = [
  { id: "gr1", target: { kind: "tag", id: "t1" }, port: null, network_id: null, subject: { kind: "group", id: "g1" } },
  { id: "gr2", target: { kind: "app", id: "a1" }, port: { port: 443, proto: "tcp" }, network_id: "n-lan", subject: { kind: "anyone" } },
  { id: "gr3", target: { kind: "app", id: "a4" }, port: null, network_id: null, subject: { kind: "peer", id: "p1" } },
  { id: "gr4", target: { kind: "app", id: "a2" }, port: null, network_id: "n-ygg", subject: { kind: "group", id: "g2" } },
  { id: "gr5", target: { kind: "tag", id: "t2" }, port: null, network_id: null, subject: { kind: "peer", id: "p3" } },
  { id: "gr6", target: { kind: "app", id: "a5" }, port: { port: 3000, proto: "tcp" }, network_id: null, subject: { kind: "anyone" } },
  { id: "gr7", target: { kind: "tag", id: "t4" }, port: null, network_id: "n-lan", subject: { kind: "peer", id: "p4" } },
  { id: "gr8", target: { kind: "app", id: "a7" }, port: null, network_id: null, subject: { kind: "peer", id: "p2" } },
];

// ─── Derived views ──────────────────────────────────────────────────────────

const credNets = (p: Peer): GrantReach[] => {
  const out: GrantReach[] = [];
  if (p.credentials.some((c) => c.kind === "ygg_key" || c.kind === "ygg_addr")) out.push({ network_id: "n-ygg", reach: "verified" });
  if (p.credentials.some((c) => c.kind === "ip")) out.push({ network_id: "n-lan", reach: "ip_only" });
  return out.length ? out : [{ network_id: "n-ygg", reach: "not_reachable" }];
};
const reachOf = (g: G): GrantReach[] => {
  const nets = networks.filter((n) => n.grants_apply && (g.network_id === null || n.id === g.network_id));
  if (g.subject.kind === "anyone") return nets.map((n) => ({ network_id: n.id, reach: "open" }));
  const ids = g.subject.kind === "peer" ? [g.subject.id] : (groups.find((x) => x.id === (g.subject as { id: string }).id)?.members ?? []);
  const all = ids.flatMap((id) => credNets(peers.find((p) => p.id === id)!)).filter((r) => nets.some((n) => n.id === r.network_id));
  return all.filter((r, i) => all.findIndex((x) => x.network_id === r.network_id && x.reach === r.reach) === i);
};
const view = (g: G): GrantView => ({ ...g, created_at: T0, reach: reachOf(g) });

function detail(a: App): AppDetail {
  const mine = grants.filter((g) => g.target.kind === "app" && g.target.id === a.id);
  const access: EffectiveAccess[] = [];
  for (const g of grants) {
    if (g.target.kind === "app" && g.target.id === a.id) {
      access.push({ grant_id: g.id, port: g.port, network_id: g.network_id, subject: g.subject, origin: g.subject.kind === "group" ? { kind: "group", group_id: g.subject.id } : { kind: "direct" } });
    } else if (g.target.kind === "tag") {
      const tag = tags.find((t) => t.id === (g.target as { id: string }).id);
      for (const m of tag?.members.filter((x) => x.app_id === a.id) ?? []) {
        access.push({ grant_id: g.id, port: m.port ?? g.port, network_id: g.network_id, subject: g.subject, origin: { kind: "tag", tag_id: g.target.id } });
      }
    }
  }
  return { ...a, grants: mine.map(view), access, tags: tags.filter((t) => t.members.some((m) => m.app_id === a.id)).map((t) => t.id), counters: [] };
}

// ─── Batches ────────────────────────────────────────────────────────────────

interface Op { op: string; [k: string]: unknown }
function changes(req: { ops: ChangeOp[]; dry_run: boolean }) {
  const snap = { grants: [...grants], tags: tags.map((t) => ({ ...t, members: [...t.members] })), peers: [...peers], apps: apps.map((a) => ({ ...a })) };
  const refs: Record<string, string> = {};
  const out: BatchChange[] = [];
  let widens = false;
  const res = (id: string) => refs[id] ?? id;
  for (const raw of req.ops) {
    const op = raw as unknown as Op;
    switch (op.op) {
      case "create_peer": {
        const p: Peer = { id: uid("p"), label: op.label as string, groups: [], created_at: T0, credentials: (op.credentials as { kind: Peer["credentials"][0]["kind"]; value: string }[]).map((c) => ({ id: uid("c"), kind: c.kind, value: c.value, label: null })) };
        if (peers.some((x) => x.label === p.label)) throw { code: "conflict", message: `operation ${out.length}: peer ${p.label} already exists` };
        if (op.ref) refs[op.ref as string] = p.id;
        peers = [...peers, p];
        out.push({ kind: "create", item: "peer", name: p.label, id: p.id, opens_to_anyone: false });
        break;
      }
      case "create_tag": {
        const t: Tag = { id: uid("t"), label: op.label as string, patterns: op.patterns as string[], members: [], excluded: [], created_at: T0 };
        if (tags.some((x) => x.label === t.label)) throw { code: "conflict", message: `operation ${out.length}: tag ${t.label} already exists` };
        if (op.ref) refs[op.ref as string] = t.id;
        tags = [...tags, t];
        out.push({ kind: "create", item: "tag", name: t.label, id: t.id, opens_to_anyone: false });
        break;
      }
      case "add_grant": {
        const subject = op.subject as Subject;
        const g: G = {
          id: uid("gr"),
          target: { kind: (op.target as { kind: "app" | "tag" }).kind, id: res((op.target as { id: string }).id) },
          port: (op.port as G["port"]) ?? null,
          network_id: (op.network_id as string) ?? null,
          subject: subject.kind === "anyone" ? subject : { kind: subject.kind, id: res(subject.id) },
        };
        if (subject.kind === "anyone" && !op.confirm_open) throw { code: "confirmation_required", message: "confirm opening to anyone" };
        grants = [...grants, g];
        const reach = reachOf(g);
        widens ||= reach.some((r) => r.reach !== "not_reachable");
        const tgt = g.target.kind === "app" ? apps.find((a) => a.id === g.target.id)?.name : `tag ${tags.find((t) => t.id === g.target.id)?.label}`;
        const who = g.subject.kind === "anyone" ? "Anyone" : g.subject.kind === "peer" ? peers.find((p) => p.id === (g.subject as { id: string }).id)?.label : `group ${groups.find((x) => x.id === (g.subject as { id: string }).id)?.label}`;
        out.push({ kind: "create", item: "grant", name: `${who} to ${tgt}${g.port ? ` ${g.port.port}/${g.port.proto}` : ""}`, detail: g.network_id ? `on ${g.network_id}` : undefined, id: g.id, opens_to_anyone: g.subject.kind === "anyone", reach });
        break;
      }
      case "remove_grant": {
        const g = grants.find((x) => x.id === op.grant_id);
        if (!g) throw { code: "not_found", message: `grant ${op.grant_id}` };
        grants = grants.filter((x) => x.id !== g.id);
        out.push({ kind: "delete", item: "grant", name: `grant ${g.id}`, id: g.id, opens_to_anyone: false, reach: reachOf(g) });
        break;
      }
      case "add_tag_member": {
        const tag = tags.find((t) => t.id === res(op.tag_id as string));
        const app = apps.find((a) => a.id === op.app_id);
        if (!tag || !app) throw { code: "not_found", message: "tag or app" };
        const tg = grants.filter((g) => g.target.kind === "tag" && g.target.id === tag.id);
        const opens = tg.some((g) => g.subject.kind === "anyone");
        if (opens && !op.confirm_open) throw { code: "confirmation_required", message: "confirm" };
        const port = (op.port as { port: number; proto: "tcp" | "udp" } | undefined) ?? null;
        if (!tag.members.some((m) => m.app_id === app.id && JSON.stringify(m.port) === JSON.stringify(port))) {
          tags = tags.map((t) => (t.id === tag.id ? { ...t, members: [...t.members, { app_id: app.id, port }] } : t));
          const reach = tg.flatMap(reachOf);
          widens ||= reach.some((r) => r.reach !== "not_reachable");
          const who = tg.map((g) => (g.subject.kind === "anyone" ? "Anyone" : g.subject.kind === "peer" ? peers.find((p) => p.id === (g.subject as { id: string }).id)?.label : `group ${groups.find((x) => x.id === (g.subject as { id: string }).id)?.label}`));
          out.push({ kind: "create", item: "tag_member", name: `${app.name} in tag ${tag.label}`, detail: who.length ? `reachable by ${who.join(", ")}` : undefined, opens_to_anyone: opens, reach });
        }
        break;
      }
      case "remove_tag_member": {
        const tag = tags.find((t) => t.id === op.tag_id)!;
        tags = tags.map((t) => (t.id === tag.id ? { ...t, members: t.members.filter((m) => !(m.app_id === op.app_id && JSON.stringify(m.port) === JSON.stringify(op.port ?? null))) } : t));
        out.push({ kind: "delete", item: "tag_member", name: `${op.app_id} from tag ${tag.label}`, opens_to_anyone: false });
        break;
      }
      case "review": {
        apps = apps.map((a) => (a.id === op.app_id ? { ...a, reviewed: op.reviewed as boolean } : a));
        out.push({ kind: "update", item: "app", name: apps.find((a) => a.id === op.app_id)?.name ?? "", opens_to_anyone: false });
        break;
      }
    }
  }
  if (req.dry_run) {
    grants = snap.grants;
    tags = snap.tags;
    peers = snap.peers;
    apps = snap.apps;
  }
  return { dry_run: req.dry_run, refs, changes: out, changes_reach: widens };
}

const done = <T,>(value: T) => ({ value, enforcement: null });

export function installMock() {
  mockIPC(
    (cmd, args) => {
      if (cmd.startsWith("plugin:")) return undefined;
      const a = (args ?? {}) as Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
      switch (cmd) {
        case "status":
          return { version: "dev", networks, protect_host_interfaces: [], disabled: false, unadopted: false, counts: { apps: apps.length, pending_apps: apps.filter((x) => !x.reviewed).length, addresses: 0, peers: peers.length, groups: groups.length, grants: grants.length } };
        case "list_apps": return apps;
        case "get_app": return detail(apps.find((x) => x.id === a.id)!);
        case "list_peers": return peers;
        case "list_groups": return groups;
        case "list_grants": return grants.map(view);
        case "list_tags": return tags;
        case "list_networks": return networks;
        case "get_settings": return { address_mode: "per_app", protect_host_interfaces: ["eth0"] };
        case "activity": return [];
        case "share_app": return { tor: [] };
        case "subscribe_events": return undefined;
        case "parse_credentials":
          return String(a.text ?? "").split(/[\s,]+/).filter(Boolean).map((input) => /[:.]/.test(input)
            ? { input, kind: "ip", normalized: input, reach: [], error: null }
            : { input, kind: null, normalized: null, reach: [], error: `cannot tell what "${input}" is` });
        case "changes": return done(changes(a.req));
        case "set_group_members":
          groups = groups.map((g) => (g.id === a.id ? { ...g, members: a.peerIds } : g));
          peers = peers.map((p) => ({ ...p, groups: groups.filter((g) => g.members.includes(p.id)).map((g) => g.id) }));
          return done(groups.find((g) => g.id === a.id));
        case "create_group": {
          const g: PeerGroup = { id: uid("g"), label: a.req.label, members: a.req.members, created_at: T0 };
          groups = [...groups, g];
          peers = peers.map((p) => ({ ...p, groups: groups.filter((x) => x.members.includes(p.id)).map((x) => x.id) }));
          return g;
        }
        default:
          throw { code: "internal", message: `dev mock: ${cmd} is not mocked` };
      }
    },
    { shouldMockEvents: true },
  );
}
