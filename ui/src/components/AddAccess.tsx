import { useEffect, useMemo, useRef, useState } from "react";
import type { ChangeOp, NewCredential, PortRef, Subject, Target } from "../api";
import { useCommit } from "../commit";
import { CREDENTIAL_PLACEHOLDER, portLabel, samePort, subjectLabel, targetLabel } from "../lib";
import { useApps, useGroups, useList, useNetworks, useParsedCredentials, usePeers, useTags } from "../queries";
import { CREDENTIAL_INFO } from "../reach";
import CommitPreview from "./CommitPreview";
import Picker, { type PickerItem } from "./Picker";

/** One side is fixed by the selection; the other is chosen here. */
export type FixedSide = { side: "targets"; targets: Target[] } | { side: "subjects"; subjects: Subject[] };

type Chip =
  | { key: string; kind: "subject"; subject: Subject; label: string }
  | { key: string; kind: "target"; target: Target; label: string }
  | { key: string; kind: "new"; text: string; label: string; credentials: NewCredential[] };

const tokens = (text: string) => text.split(/[\s,]+/).filter(Boolean);

/** Give access: the selection fills one side, a picker chooses the other. Ports and networks are
 * optional. Pasting a key, address or IP creates a peer on the way. */
export default function AddAccess({ fixed }: { fixed: FixedSide }) {
  const apps = useList(useApps());
  const tags = useList(useTags());
  const peers = useList(usePeers());
  const groups = useList(useGroups());
  const networks = useList(useNetworks());

  const [open, setOpen] = useState(false);
  const [chips, setChips] = useState<Chip[]>([]);
  const [allPorts, setAllPorts] = useState(true);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [nets, setNets] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  const [pickerOpen, setPickerOpen] = useState(false);
  const counter = useRef(0);

  const reset = () => {
    setOpen(false);
    setChips([]);
    setAllPorts(true);
    setPicked(new Set());
    setNets(new Set());
  };
  const commit = useCommit(reset);

  const choosingSubjects = fixed.side === "targets";

  // The targets whose ports can be chosen: the selection, or what was picked.
  const targets: Target[] = useMemo(
    () => (fixed.side === "targets" ? fixed.targets : chips.flatMap((c) => (c.kind === "target" ? [c.target] : []))),
    [fixed, chips],
  );
  const portOptions = useMemo(() => {
    const out = new Map<string, PortRef>();
    const addApp = (appId: string, only: PortRef | null) => {
      for (const p of apps.find((a) => a.id === appId)?.ports ?? []) {
        if (only === null || samePort(only, p)) out.set(portLabel(p), { port: p.port, proto: p.proto });
      }
    };
    for (const t of targets) {
      if (t.kind === "app") addApp(t.id, null);
      else for (const m of tags.find((x) => x.id === t.id)?.members ?? []) addApp(m.app_id, m.port);
    }
    return [...out.values()].sort((a, b) => a.port - b.port || a.proto.localeCompare(b.proto));
  }, [targets, apps, tags]);
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
      ...apps.filter((a) => !a.system).map<PickerItem>((a) => ({ id: `app:${a.id}`, label: a.name, section: "Apps", state: has(`app:${a.id}`) ? "on" : "off" })),
      ...apps.filter((a) => a.system).map<PickerItem>((a) => ({ id: `app:${a.id}`, label: a.name, section: "System services", state: has(`app:${a.id}`) ? "on" : "off" })),
    ];
  }, [fixed.side, chips, groups, peers, tags, apps]);

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
          : { key: item.id, kind: "target", target: { kind: kind as "app" | "tag", id: ref }, label: item.label };
    setChips([...chips, chip]);
  };
  const createPeer = () => {
    if (!parsedOk || !parsed.data) return;
    const credentials = parsed.data.map((p) => ({ kind: p.kind!, value: p.normalized!, label: null }));
    setChips([...chips, { key: `new${counter.current++}`, kind: "new", text: query, label: "", credentials }]);
  };

  // ─── The operations ────────────────────────────────────────────────────────
  const newPeers = chips.filter((c): c is Extract<Chip, { kind: "new" }> => c.kind === "new");
  const chosen = chips.length;
  const portSelection: (PortRef | undefined)[] = allPorts ? [undefined] : portOptions.filter((p) => picked.has(portLabel(p)));
  const ready =
    targets.length > 0 && chosen > 0 && (fixed.side === "targets" || fixed.subjects.length > 0) &&
    portSelection.length > 0 && newPeers.every((c) => c.label.trim() !== "");

  const ops = useMemo<ChangeOp[]>(() => {
    if (!ready) return [];
    const out: ChangeOp[] = [];
    const subjectOf = new Map<string, Subject>();
    newPeers.forEach((c, i) => {
      out.push({ op: "create_peer", ref: `$new${i}`, label: c.label.trim(), credentials: c.credentials });
      subjectOf.set(c.key, { kind: "peer", id: `$new${i}` });
    });
    const subjects: Subject[] =
      fixed.side === "subjects"
        ? fixed.subjects
        : chips.flatMap((c) => (c.kind === "subject" ? [c.subject] : c.kind === "new" ? [subjectOf.get(c.key)!] : []));
    for (const target of targets) {
      for (const port of portSelection) {
        for (const subject of subjects) {
          for (const network_id of nets.size === 0 ? [undefined] : [...nets]) {
            out.push({
              op: "add_grant",
              target,
              ...(port ? { port } : {}),
              ...(network_id ? { network_id } : {}),
              subject,
              confirm_open: false,
            });
          }
        }
      }
    }
    return out;
    // portSelection and newPeers derive from chips, picked, allPorts and portOptions.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready, fixed, chips, targets, allPorts, picked, portOptions, nets]);

  // A review of an earlier form is stale as soon as the form changes.
  const opsKey = JSON.stringify(ops);
  const { cancel } = commit;
  useEffect(() => {
    cancel();
  }, [opsKey, cancel]);

  // The review has its own Apply and Cancel.
  const reviewing = commit.state.phase === "review" || commit.state.phase === "confirm";
  const grantCount = ops.filter((o) => o.op === "add_grant").length;
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (ready) void commit.runBatch(ops, `Access added (${grantCount})`);
  };

  const fixedNames =
    fixed.side === "targets"
      ? fixed.targets.map((t) => targetLabel(t, apps, tags))
      : fixed.subjects.map((s) => subjectLabel(s, peers, groups));
  const summary = fixedNames.length > 3 ? `${fixedNames.slice(0, 3).join(", ")} and ${fixedNames.length - 3} more` : fixedNames.join(", ");

  if (!open) {
    return (
      <div className="add-access">
        <button className="btn btn-primary btn-sm" onClick={() => setOpen(true)}>Add access…</button>
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

      {chips.length > 0 && (
        <ul className="chip-row" aria-label={choosingSubjects ? "Chosen subjects" : "Chosen targets"}>
          {chips.map((c) => (
            <li key={c.key} className={`subject-chip${c.kind === "new" ? " subject-chip-new" : ""}`}>
              {c.kind === "new" ? (
                <NewPeer chip={c} onLabel={(label) => setChips(chips.map((x) => (x.key === c.key ? { ...c, label } : x)))} />
              ) : (
                <span>{c.label}</span>
              )}
              <button type="button" className="chip-x" aria-label={`Remove ${c.kind === "new" ? c.text : c.label}`} onClick={() => setChips(chips.filter((x) => x.key !== c.key))}>
                ×
              </button>
            </li>
          ))}
        </ul>
      )}

      <Picker
        label={choosingSubjects ? "Who" : "What"}
        trigger={choosingSubjects ? "Choose who…" : "Choose apps or tags…"}
        triggerClass="btn btn-sm"
        placeholder={choosingSubjects ? `Search, or paste a key, address or IP (${CREDENTIAL_PLACEHOLDER})` : "Search apps and tags"}
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
                    New peer from <span className="mono">{query.length > 36 ? `${query.slice(0, 33)}…` : query}</span>
                  </>
                ),
                pick: createPeer,
              })
            : undefined
        }
      />

      <details className="add-limits">
        <summary>Limit to ports or networks (optional)</summary>
        <fieldset className="field-group">
          <legend>Ports</legend>
          <label className="check">
            <input type="checkbox" checked={allPorts} onChange={(e) => setAllPorts(e.target.checked)} />
            All ports
          </label>
          {!allPorts && portOptions.length === 0 && <p className="muted">Nothing chosen has ports yet.</p>}
          {!allPorts &&
            portOptions.map((p) => (
              <label key={portLabel(p)} className="check">
                <input
                  type="checkbox"
                  checked={picked.has(portLabel(p))}
                  onChange={(e) => {
                    const next = new Set(picked);
                    if (e.target.checked) next.add(portLabel(p));
                    else next.delete(portLabel(p));
                    setPicked(next);
                  }}
                />
                {portLabel(p)}
              </label>
            ))}
        </fieldset>
        <fieldset className="field-group">
          <legend>Networks</legend>
          <p className="hint">None ticked: every network that takes grants. Anyone on one network means everyone on it.</p>
          {grantNetworks.map((n) => (
            <label key={n.id} className="check">
              <input
                type="checkbox"
                checked={nets.has(n.id)}
                onChange={(e) => {
                  const next = new Set(nets);
                  if (e.target.checked) next.add(n.id);
                  else next.delete(n.id);
                  setNets(next);
                }}
              />
              {n.name}
            </label>
          ))}
        </fieldset>
      </details>

      {reviewing ? null : (
        <div className="actions">
          <button type="submit" className="btn btn-primary btn-sm" disabled={!ready || commit.state.phase === "checking" || commit.state.phase === "applying"}>
            Add access
          </button>
          <button type="button" className="btn btn-sm" onClick={reset}>Cancel</button>
        </div>
      )}
      <CommitPreview commit={commit} title="This gives access" />
    </form>
  );
}

function NewPeer({ chip, onLabel }: { chip: Extract<Chip, { kind: "new" }>; onLabel: (l: string) => void }) {
  const kinds = [...new Set(chip.credentials.map((c) => CREDENTIAL_INFO[c.kind].name))].join(", ");
  const short = chip.text.length > 20 ? `${chip.text.slice(0, 17)}…` : chip.text;
  return (
    <span className="new-peer">
      <span className="badge badge-pending">new peer</span>{" "}
      <input className="input input-sm" aria-label={`Label for new peer ${short}`} placeholder="label" value={chip.label} onChange={(e) => onLabel(e.target.value)} />{" "}
      <span className="muted">{kinds}</span>
    </span>
  );
}
