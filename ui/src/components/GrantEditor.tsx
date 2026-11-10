import { useEffect, useId, useMemo, useRef, useState } from "react";
import {
  toDaemonError, type ChangeOp, type NewCredential, type PortRef, type Subject, type Target,
} from "../api";
import { ChangeList, confirmAll, opensToAnyone, useDryRun } from "../batch";
import { CREDENTIAL_PLACEHOLDER, errorText, openWording, portLabel, samePort, splitOperationError, targetLabel } from "../lib";
import {
  useApps, useChanges, useGroups, useNetworks, useParsedCredentials, usePeers, useTags,
} from "../queries";
import { CREDENTIAL_INFO } from "../reach";
import ConfirmDialog from "./ConfirmDialog";
import { useToast } from "./Toast";

interface Props {
  /** The apps (or tags) to grant access to. One dialog serves 1 or N of them. */
  targets: Target[];
  /** Ports to start with ticked; without them "all ports" is ticked. */
  ports?: PortRef[];
  onClose: () => void;
}

type Chip =
  | { key: string; kind: "subject"; subject: Subject; label: string }
  | { key: string; kind: "new"; text: string; label: string; credentials: NewCredential[] };

const OPEN_SUBJECT: Subject = { kind: "anyone" };

export default function GrantEditor({ targets, ports: initialPorts = [], onClose }: Props) {
  const id = useId();
  const toast = useToast();
  const apps = useApps();
  const tags = useTags();
  const peers = usePeers();
  const groups = useGroups();
  const networks = useNetworks();
  const changes = useChanges();

  const [allPorts, setAllPorts] = useState(initialPorts.length === 0);
  const [picked, setPicked] = useState<Set<string>>(new Set(initialPorts.map(portLabel)));
  const [chips, setChips] = useState<Chip[]>([]);
  const [nets, setNets] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  const [asking, setAsking] = useState(false);
  const [applyError, setApplyError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const counter = useRef(0);
  const queryRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    queryRef.current?.focus();
  }, []);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !asking) onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [asking, onClose]);

  // ─── What can be chosen ───────────────────────────────────────────────────
  const appList = apps.data ?? [];
  const tagList = useMemo(() => tags.data ?? [], [tags.data]);
  const portOptions = useMemo(() => {
    const out = new Map<string, PortRef>();
    const addApp = (appId: string, only: PortRef | null) => {
      const app = (apps.data ?? []).find((a) => a.id === appId);
      for (const p of app?.ports ?? []) {
        if (only === null || samePort(only, p)) out.set(portLabel(p), { port: p.port, proto: p.proto });
      }
    };
    for (const t of targets) {
      if (t.kind === "app") addApp(t.id, null);
      else for (const m of tagList.find((x) => x.id === t.id)?.members ?? []) addApp(m.app_id, m.port);
    }
    return [...out.values()].sort((a, b) => a.port - b.port || a.proto.localeCompare(b.proto));
  }, [targets, apps.data, tagList]);
  const grantNetworks = (networks.data ?? []).filter((n) => n.grants_apply);

  // ─── The subject chip field ───────────────────────────────────────────────
  const parsed = useParsedCredentials(query);
  const taken = new Set(chips.flatMap((c) => (c.kind === "subject" ? [c.key] : [])));
  const q = query.trim().toLowerCase();
  const suggestions: Chip[] = [];
  const matches = (label: string) => !q || label.toLowerCase().includes(q);
  if (matches("anyone") && !taken.has("anyone")) {
    suggestions.push({ key: "anyone", kind: "subject", subject: OPEN_SUBJECT, label: "Anyone" });
  }
  for (const p of peers.data ?? []) {
    if (matches(p.label) && !taken.has(`peer:${p.id}`)) {
      suggestions.push({ key: `peer:${p.id}`, kind: "subject", subject: { kind: "peer", id: p.id }, label: p.label });
    }
  }
  for (const g of groups.data ?? []) {
    if (matches(g.label) && !taken.has(`group:${g.id}`)) {
      suggestions.push({ key: `group:${g.id}`, kind: "subject", subject: { kind: "group", id: g.id }, label: `group ${g.label}` });
    }
  }
  const parsedOk =
    q !== "" && parsed.data && parsed.data.length > 0 && parsed.data.every((p) => p.error === null && p.kind !== null && p.normalized !== null);
  const parseError = q !== "" && parsed.data?.find((p) => p.error !== null)?.error;
  const newPeerOption = parsedOk && !suggestions.some((s) => s.label.toLowerCase() === q);

  const addChip = (c: Chip) => {
    setChips((cs) => [...cs, c]);
    setQuery("");
    queryRef.current?.focus();
  };
  const addNewPeer = () => {
    if (!parsed.data || !parsedOk) return;
    const credentials = parsed.data.map((p) => ({ kind: p.kind!, value: p.normalized!, label: null }));
    addChip({ key: `new${counter.current++}`, kind: "new", text: query.trim(), label: "", credentials });
  };

  // ─── The operations ───────────────────────────────────────────────────────
  const newPeers = chips.filter((c): c is Extract<Chip, { kind: "new" }> => c.kind === "new");
  const portSelection: (PortRef | undefined)[] = allPorts
    ? [undefined]
    : portOptions.filter((p) => picked.has(portLabel(p)));
  const ready =
    targets.length > 0 &&
    chips.length > 0 &&
    portSelection.length > 0 &&
    newPeers.every((c) => c.label.trim() !== "");

  const ops = useMemo(() => {
    if (!ready) return [] as ChangeOp[];
    const out: ChangeOp[] = [];
    const subjectOf = new Map<string, Subject>();
    newPeers.forEach((c, i) => {
      const ref = `$new${i}`;
      out.push({ op: "create_peer", ref, label: c.label.trim(), credentials: c.credentials });
      subjectOf.set(c.key, { kind: "peer", id: ref });
    });
    for (const target of targets) {
      for (const port of portSelection) {
        for (const c of chips) {
          const subject = c.kind === "new" ? subjectOf.get(c.key)! : c.subject;
          for (const network_id of nets.size === 0 ? [undefined] : [...nets]) {
            out.push({
              op: "add_grant",
              target,
              ...(port ? { port } : {}),
              ...(network_id ? { network_id } : {}),
              subject,
              confirm_open: subject.kind === "anyone",
            });
          }
        }
      }
    }
    return out;
    // portSelection and newPeers derive from chips/picked/allPorts/portOptions.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready, targets, chips, allPorts, picked, portOptions, nets]);

  const dry = useDryRun(ops);
  const failure = applyError ?? (dry.state === "error" ? dry.message : null);
  const failed = failure === null ? null : splitOperationError(failure);
  // An error in an operation that creates a peer belongs to that peer's chip.
  const chipError = (c: Chip): string | null => {
    if (!failed || failed.index === null || c.kind !== "new") return null;
    return newPeers[failed.index]?.key === c.key ? failed.text : null;
  };
  const generalError = failed && !(failed.index !== null && failed.index < newPeers.length) ? failed.text : null;

  const networkNames = grantNetworks.filter((n) => nets.has(n.id)).map((n) => n.name);
  const openWord = openWording(networkNames).replace(/^Anyone$/, "anyone").replace(/^Everyone/, "everyone");

  async function apply(confirmed: boolean) {
    setApplyError(null);
    setBusy(true);
    try {
      await changes.mutateAsync({ ops: confirmed ? confirmAll(ops) : ops, dryRun: false });
      toast.success(`Access granted (${ops.filter((o) => o.op === "add_grant").length})`);
      onClose();
    } catch (e) {
      if (toDaemonError(e).code === "confirmation_required") setAsking(true);
      else setApplyError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    if (opensToAnyone(ops)) setAsking(true);
    else void apply(false);
  };

  const targetNames = targets.map((t) => targetLabel(t, appList, tagList));
  const grantCount = ops.filter((o) => o.op === "add_grant").length;

  return (
    <>
      <div className="modal-overlay" onClick={onClose}>
        <form
          className="modal modal-wide"
          role="dialog"
          aria-modal="true"
          aria-labelledby={`${id}-t`}
          onClick={(e) => e.stopPropagation()}
          onSubmit={onSubmit}
        >
          <h2 id={`${id}-t`} className="modal-title">Grant access</h2>
          <p className="muted">
            To: <strong>{targetNames.join(", ") || "…"}</strong>
          </p>

          <fieldset className="field-group">
            <legend>Ports</legend>
            <label className="check">
              <input type="checkbox" checked={allPorts} onChange={(e) => setAllPorts(e.target.checked)} />
              All ports
            </label>
            {!allPorts && portOptions.length === 0 && <p className="muted">These apps have no ports yet.</p>}
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

          <div className="form-row">
            <label htmlFor={`${id}-who`}>Who</label>
            <ul className="chip-row" aria-label="Chosen subjects">
              {chips.map((c) => (
                <li key={c.key} className={`subject-chip${c.kind === "new" ? " subject-chip-new" : ""}`}>
                  {c.kind === "subject" ? (
                    <span>{c.label}</span>
                  ) : (
                    <NewPeerChip
                      chip={c}
                      error={chipError(c)}
                      onLabel={(label) => setChips(chips.map((x) => (x.key === c.key ? { ...c, label } : x)))}
                    />
                  )}
                  <button
                    type="button"
                    className="chip-x"
                    aria-label={`Remove ${c.kind === "subject" ? c.label : c.text}`}
                    onClick={() => setChips(chips.filter((x) => x.key !== c.key))}
                  >
                    ×
                  </button>
                </li>
              ))}
            </ul>
            <input
              id={`${id}-who`}
              ref={queryRef}
              className="input"
              role="combobox"
              aria-expanded={suggestions.length > 0 || newPeerOption}
              aria-controls={`${id}-list`}
              autoComplete="off"
              placeholder={`A peer, a group, Anyone, or paste a key, address or IP (${CREDENTIAL_PLACEHOLDER})`}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key !== "Enter") return;
                e.preventDefault();
                if (suggestions[0]) addChip(suggestions[0]);
                else if (newPeerOption) addNewPeer();
              }}
            />
            <ul id={`${id}-list`} role="listbox" aria-label="Suggestions" className="suggestions">
              {suggestions.slice(0, 8).map((s) => (
                <li key={s.key} role="option" aria-selected={false}>
                  <button type="button" className="suggestion" onClick={() => addChip(s)}>{s.label}</button>
                </li>
              ))}
              {newPeerOption && (
                <li role="option" aria-selected={false}>
                  <button type="button" className="suggestion" onClick={addNewPeer}>
                    New peer from <span className="mono">{query.trim().length > 40 ? `${query.trim().slice(0, 37)}…` : query.trim()}</span>
                  </button>
                </li>
              )}
            </ul>
            {parseError && suggestions.length === 0 && <p className="hint field-error">{parseError}</p>}
          </div>

          <fieldset className="field-group">
            <legend>Networks</legend>
            <p className="hint">None ticked: every network that takes grants.</p>
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

          <section aria-label="Preview" className="preview">
            <h3 className="section-title">What this does{grantCount > 0 ? ` (${grantCount} grants)` : ""}</h3>
            {!ready && <p className="muted">Choose who gets access{newPeers.some((c) => !c.label.trim()) ? " and name the new peers" : ""}.</p>}
            {ready && dry.state === "loading" && <p className="muted">Checking…</p>}
            {ready && dry.state === "ok" && <ChangeList changes={dry.result.changes} networks={networks.data ?? []} />}
          </section>

          {generalError && <div className="error-banner" role="alert">{generalError}</div>}
          <div className="modal-actions">
            <button type="button" className="btn" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={busy || !ready || dry.state === "error"}>
              Grant
            </button>
          </div>
        </form>
      </div>
      {asking && (
        <ConfirmDialog
          title={`Open to ${openWord}?`}
          confirmLabel={`Open to ${openWord}`}
          onCancel={() => setAsking(false)}
          onConfirm={() => {
            setAsking(false);
            void apply(true);
          }}
        >
          <p>
            {networkNames.length > 0
              ? `Any host on ${networkNames.join(", ")} will be able to connect, nothing is verified. Hosts on other networks, even when routed here, will not.`
              : "Any source that can reach this machine on the apps' networks will be able to connect. This is not limited to your peers."}
          </p>
        </ConfirmDialog>
      )}
    </>
  );
}

function NewPeerChip({ chip, error, onLabel }: { chip: Extract<Chip, { kind: "new" }>; error: string | null; onLabel: (l: string) => void }) {
  const kinds = [...new Set(chip.credentials.map((c) => CREDENTIAL_INFO[c.kind].name))].join(", ");
  return (
    <span className="new-peer">
      <span className="badge badge-pending">new peer</span>{" "}
      <input
        className="input input-sm"
        aria-label={`Label for new peer ${chip.text.length > 20 ? `${chip.text.slice(0, 17)}…` : chip.text}`}
        placeholder="label"
        value={chip.label}
        onChange={(e) => onLabel(e.target.value)}
      />{" "}
      <span className="muted">{kinds}</span>
      {error && <span className="field-error"> {error}</span>}
    </span>
  );
}
