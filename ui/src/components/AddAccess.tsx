import { useMemo, useRef, useState } from "react";
import type { ChangeOp, NewCredential, Scope, Subject, Target } from "../api";
import { useCommit } from "../commit";
import { ALL_SCOPE, portLabel, portOfScope, scopeKey, scopeLabel, scopeOfPort, subjectLabel, targetLabel } from "../lib";
import { useApps, useGroups, useList, useNetworks, useParsedCredentials, usePeers, useReservations, usePortGroups, useTags } from "../queries";
import { CREDENTIAL_INFO } from "../reach";
import CommitPreview from "./CommitPreview";
import { useFormOpen } from "./ActionRow";
import Picker, { type PickerItem } from "./Picker";

/** One side is fixed by the selection; the other is chosen here. */
export type FixedSide = { side: "targets"; targets: Target[] } | { side: "subjects"; subjects: Subject[] };

type Chip =
  | { key: string; kind: "subject"; subject: Subject; label: string }
  | { key: string; kind: "target"; target: Target; label: string }
  | { key: string; kind: "new"; text: string; label: string; credentials: NewCredential[] };

interface Props {
  fixed: FixedSide;
  /** The "Add access" of a row: the form opens with only this row chosen. */
  preselect?: Scope;
  /** Names the row for assistive technology ("Add access to 443/tcp"). */
  rowLabel?: string;
  /** The form was cancelled or applied. */
  onDone?: () => void;
}

/** One thing a grant can name: All ports, a port, or a port group. */
interface Option {
  key: string;
  scope: Scope;
  label: string;
  mono: boolean;
}

const tokens = (text: string) => text.split(/[\s,]+/).filter(Boolean);

/** Give access: the selection fills one side, a picker chooses the other. What to open is chosen
 * explicitly: All ports, some ports or some port groups. Networks are optional. Pasting keys, addresses
 * or IPs creates one peer per value on the way, named by the daemon. */
export default function AddAccess({ fixed, preselect, rowLabel, onDone }: Props) {
  const apps = useList(useApps());
  const tags = useList(useTags());
  const peers = useList(usePeers());
  const groups = useList(useGroups());
  const networks = useList(useNetworks());
  const portGroups = useList(usePortGroups());
  const reservations = useList(useReservations());

  const [open, setOpen] = useState(false);
  const stepAside = useFormOpen(open);
  const [chips, setChips] = useState<Chip[]>([]);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [nets, setNets] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  const [pickerOpen, setPickerOpen] = useState(false);
  const counter = useRef(0);

  const reset = () => {
    setOpen(false);
    setChips([]);
    setPicked(new Set());
    setNets(new Set());
    onDone?.();
  };
  const commit = useCommit(reset);

  const choosingSubjects = fixed.side === "targets";

  // The targets whose rows can be chosen: the selection, or what was picked.
  const targets: Target[] = useMemo(
    () => (fixed.side === "targets" ? fixed.targets : chips.flatMap((c) => (c.kind === "target" ? [c.target] : []))),
    [fixed, chips],
  );
  // What a grant can name: All ports, the detected ports and the attached port groups of the apps
  // (a group chip needs the group on at least one of them), and for a tag every port group.
  const options = useMemo<Option[]>(() => {
    const ports = new Map<string, Option>();
    const groupIds = new Set<string>();
    const addApp = (appId: string, only: Scope | null) => {
      for (const p of apps.find((a) => a.id === appId)?.ports ?? []) {
        const scope = scopeOfPort(p);
        if (only === null || only.kind === "all" || scopeKey(only) === scopeKey(scope)) {
          ports.set(scopeKey(scope), { key: scopeKey(scope), scope, label: portLabel(p), mono: true });
        }
      }
      for (const g of portGroups) if (g.apps.includes(appId)) groupIds.add(g.id);
    };
    let anyTag = false;
    for (const t of targets) {
      if (t.kind === "app") addApp(t.id, null);
      else if (t.kind === "reservation") continue;
      else {
        anyTag = true;
        for (const m of tags.find((x) => x.id === t.id)?.members ?? []) addApp(m.app_id, portOfScope(m.scope) ? m.scope : null);
      }
    }
    const sorted = [...ports.values()].sort((a, b) => (a.scope.kind === "port" && b.scope.kind === "port" ? a.scope.port - b.scope.port || a.scope.proto.localeCompare(b.scope.proto) : 0));
    const groups = portGroups
      .filter((g) => anyTag || groupIds.has(g.id))
      .map<Option>((g) => ({ key: `group:${g.id}`, scope: { kind: "group", id: g.id }, label: g.label, mono: false }));
    return [{ key: "*", scope: ALL_SCOPE, label: scopeLabel(ALL_SCOPE), mono: false }, ...sorted, ...groups];
  }, [targets, apps, tags, portGroups]);
  const grantNetworks = networks.filter((n) => n.grants_apply);

  // ─── The picker ────────────────────────────────────────────────────────────
  const parsed = useParsedCredentials(choosingSubjects ? query : "");
  const words = tokens(query);
  const parsedOk =
    choosingSubjects && words.length > 0 && parsed.data !== undefined && parsed.data.length === words.length &&
    parsed.data.every((p, i) => p.input === words[i] && p.error === null && p.kind !== null && p.normalized !== null);

  const items: PickerItem[] = useMemo(() => {
    const has = (key: string) => chips.some((c) => c.key === key);
    if (fixed.side === "targets") {
      return [
        { id: "anyone", label: "Anyone", hint: "open to everyone", section: "Everyone", state: has("anyone") ? "on" : "off" },
        ...groups.map<PickerItem>((g) => ({ id: `group:${g.id}`, label: `group ${g.label}`, section: "Groups", state: has(`group:${g.id}`) ? "on" : "off" })),
        ...peers.map<PickerItem>((p) => ({ id: `peer:${p.id}`, label: p.label, section: "Peers", state: has(`peer:${p.id}`) ? "on" : "off" })),
      ];
    }
    return [
      ...tags.map<PickerItem>((t) => ({ id: `tag:${t.id}`, label: t.label, hint: `${t.members.length} apps`, section: "Tags", state: has(`tag:${t.id}`) ? "on" : "off" })),
      ...reservations.map<PickerItem>((r) => ({ id: `reservation:${r.id}`, label: `reserved ${r.label}`, hint: "All ports", section: "Reserved addresses", state: has(`reservation:${r.id}`) ? "on" : "off" })),
      ...apps.filter((a) => !a.system).map<PickerItem>((a) => ({ id: `app:${a.id}`, label: a.name, section: "Apps", state: has(`app:${a.id}`) ? "on" : "off" })),
      ...apps.filter((a) => a.system).map<PickerItem>((a) => ({ id: `app:${a.id}`, label: a.name, section: "System services", state: has(`app:${a.id}`) ? "on" : "off" })),
    ];
  }, [fixed.side, chips, groups, peers, tags, apps, reservations]);

  const toggle = (item: PickerItem) => {
    if (chips.some((c) => c.key === item.id)) {
      setChips(chips.filter((c) => c.key !== item.id));
      return;
    }
    const [kind, ref] = item.id.split(":");
    const chip: Chip =
      item.id === "anyone"
        ? { key: item.id, kind: "subject", subject: { kind: "anyone" }, label: "Anyone" }
        : kind === "group" || kind === "peer"
          ? { key: item.id, kind: "subject", subject: { kind, id: ref }, label: item.label }
          : { key: item.id, kind: "target", target: { kind: kind as "app" | "tag" | "reservation", id: ref }, label: item.label };
    setChips([...chips, chip]);
  };
  // One peer per pasted value.
  const createPeers = () => {
    if (!parsedOk || !parsed.data) return;
    const fresh = parsed.data.map<Chip>((p) => ({
      key: `new${counter.current++}`,
      kind: "new",
      text: p.input,
      label: p.input,
      credentials: [{ kind: p.kind!, value: p.normalized!, label: null }],
    }));
    setChips([...chips, ...fresh]);
  };

  // ─── The operations ────────────────────────────────────────────────────────
  const newPeers = chips.filter((c): c is Extract<Chip, { kind: "new" }> => c.kind === "new");
  const chosen = chips.length;
  const scopeSelection = options.filter((o) => picked.has(o.key));
  const ready = targets.length > 0 && chosen > 0 && (fixed.side === "targets" || fixed.subjects.length > 0) && scopeSelection.length > 0;
  // A port group is only granted on the apps it is attached to.
  const applies = (t: Target, s: Scope) =>
    t.kind === "reservation" ? s.kind === "all" : s.kind !== "group" || t.kind === "tag" || (portGroups.find((g) => g.id === s.id)?.apps.includes(t.id) ?? false);

  const ops = useMemo<ChangeOp[]>(() => {
    if (!ready) return [];
    const out: ChangeOp[] = [];
    const subjectOf = new Map<string, Subject>();
    newPeers.forEach((c, i) => {
      out.push({ op: "create_peer", ref: `$new${i}`, credentials: c.credentials });
      subjectOf.set(c.key, { kind: "peer", id: `$new${i}` });
    });
    const subjects: Subject[] =
      fixed.side === "subjects"
        ? fixed.subjects
        : chips.flatMap((c) => (c.kind === "subject" ? [c.subject] : c.kind === "new" ? [subjectOf.get(c.key)!] : []));
    for (const target of targets) {
      for (const { scope } of scopeSelection.filter((o) => applies(target, o.scope))) {
        for (const subject of subjects) {
          for (const network_id of nets.size === 0 ? [undefined] : [...nets]) {
            out.push({
              op: "add_grant",
              target,
              scope,
              ...(network_id ? { network_id } : {}),
              subject,
              confirm_open: false,
            });
          }
        }
      }
    }
    return out;
    // scopeSelection and newPeers derive from chips, picked and options.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready, fixed, chips, targets, picked, options, nets, portGroups]);

  const grantCount = ops.filter((o) => o.op === "add_grant").length;
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (ready && grantCount > 0) void commit.runBatch(ops, `Access added (${grantCount})`);
  };

  const fixedNames =
    fixed.side === "targets"
      ? fixed.targets.map((t) => targetLabel(t, apps, tags, reservations))
      : fixed.subjects.map((s) => subjectLabel(s, peers, groups));
  const summary = fixedNames.length > 3 ? `${fixedNames.slice(0, 3).join(", ")} and ${fixedNames.length - 3} more` : fixedNames.join(", ");

  if (stepAside) return null;
  if (!open) {
    const start = () => {
      if (preselect) setPicked(new Set([scopeKey(preselect)]));
      setOpen(true);
    };
    return (
      <div className="add-access">
        {preselect ? (
          <button className="btn btn-sm" aria-label={rowLabel ? `Add access to ${rowLabel}` : undefined} onClick={start}>Add access</button>
        ) : (
          <button className="btn btn-sm" onClick={start}>Add access…</button>
        )}
      </div>
    );
  }
  return (
    <form className="add-access add-form" aria-label="Add access" onSubmit={submit}>
      <p className="add-lead">
        {choosingSubjects ? "Who can reach " : "What can "}
        <strong>{summary}</strong>
        {choosingSubjects ? "?" : " reach?"}
      </p>

      <Picker
        label={choosingSubjects ? "Who" : "What"}
        field={
          chips.length > 0 ? (
            <ul className="chip-row" aria-label={choosingSubjects ? "Chosen subjects" : "Chosen targets"}>
              {chips.map((c) => (
                <li key={c.key} className={`subject-chip${c.kind === "new" ? " subject-chip-new" : ""}`}>
                  {c.kind === "new" ? <NewPeer chip={c} /> : <span>{c.label}</span>}
                  <button type="button" className="btn-icon" aria-label={`Remove ${c.label}`} title={`Remove ${c.label}`} onClick={() => setChips(chips.filter((x) => x.key !== c.key))}>
                    ×
                  </button>
                </li>
              ))}
            </ul>
          ) : null
        }
        placeholder={choosingSubjects ? "Peer, group, Anyone — or paste a key or address" : "App, tag or reserved address"}
        items={items}
        onToggle={toggle}
        onQuery={setQuery}
        open={pickerOpen}
        onOpenChange={setPickerOpen}
        create={
          choosingSubjects && parsedOk
            ? () => ({
                label: (
                  <>
                    {words.length > 1 ? `${words.length} new peers from ` : "New peer from "}
                    <span className="mono">{query.length > 36 ? `${query.slice(0, 33)}…` : query}</span>
                  </>
                ),
                pick: createPeers,
              })
            : undefined
        }
      />

      {targets.length > 0 && (
        <div className="scope-row" role="group" aria-label="What to open">
          {options.map((o) => (
            <button
              key={o.key}
              type="button"
              className={`scope-chip${o.mono ? " mono" : ""}`}
              aria-pressed={picked.has(o.key)}
              onClick={() => {
                // All ports covers the rest, so it and the narrower choices exclude each other.
                const next = new Set(o.key === "*" ? [] : [...picked].filter((k) => k !== "*"));
                if (!picked.has(o.key)) next.add(o.key);
                else if (o.key !== "*") next.delete(o.key);
                setPicked(next);
              }}
            >
              {o.label}
            </button>
          ))}
          {scopeSelection.length === 0 && <span className="hint">Choose what to open</span>}
        </div>
      )}

      {grantNetworks.length > 1 && (
        <div className="scope-row" role="group" aria-label="Networks">
          <button type="button" className="scope-chip" aria-pressed={nets.size === 0} onClick={() => setNets(new Set())}>
            All networks
          </button>
          {grantNetworks.map((n) => (
            <button
              key={n.id}
              type="button"
              className="scope-chip"
              aria-pressed={nets.has(n.id)}
              onClick={() => {
                // A specific network replaces "All networks"; none left means all again.
                const next = new Set(nets);
                if (next.has(n.id)) next.delete(n.id);
                else next.add(n.id);
                setNets(next);
              }}
            >
              {n.name}
            </button>
          ))}
        </div>
      )}

      <div className="actions">
        <button type="submit" className="btn btn-primary btn-sm" disabled={!ready || grantCount === 0 || commit.state.phase === "checking" || commit.state.phase === "applying"}>
          Add access
        </button>
        <button type="button" className="btn btn-sm" onClick={reset}>Cancel</button>
      </div>
      <CommitPreview commit={commit} title="Give access?" confirmLabel="Give access" />
    </form>
  );
}

function NewPeer({ chip }: { chip: Extract<Chip, { kind: "new" }> }) {
  const kinds = [...new Set(chip.credentials.map((c) => CREDENTIAL_INFO[c.kind].name))].join(", ");
  return (
    <span className="new-peer">
      <span className="badge badge-pending">new peer</span>
      <span className="mono new-peer-name" title={chip.text}>{chip.text}</span>
      <span className="muted">{kinds}</span>
    </span>
  );
}
