import type { CredentialKind, Reach } from "./api";

interface BadgeInfo {
  label: string;
  tip: string;
  cls: string;
}

export const REACH_INFO: Record<Reach, BadgeInfo> = {
  verified: {
    label: "verified by key",
    tip: "The network checks the sender's key, so this source cannot be forged.",
    cls: "ok",
  },
  whole_subnet: {
    label: "whole subnet",
    tip: "Everything behind this peer's subnet is allowed, not just one host.",
    cls: "warn",
  },
  ip_only: {
    label: "IP only",
    tip: "Allowed by source address only; someone who can fake that address could get in.",
    cls: "warn",
  },
  open: {
    label: "open to anyone",
    tip: "Any source on this network can connect.",
    cls: "bad",
  },
  not_reachable: {
    label: "not reachable here",
    tip: "This peer has no credential that works on this network, so nothing is allowed.",
    cls: "muted",
  },
};

export function ReachBadge({ reach, network }: { reach: Reach; network?: string }) {
  const info = REACH_INFO[reach];
  const text = network ? `${network}: ${info.label}` : info.label;
  return (
    <span
      className={`badge reach reach-${info.cls}`}
      title={info.tip}
      tabIndex={0}
      aria-label={`${text}. ${info.tip}`}
    >
      {text}
    </span>
  );
}

export const CREDENTIAL_INFO: Record<CredentialKind, BadgeInfo & { name: string }> = {
  ygg_key: { name: "Yggdrasil key", label: "verified", tip: "Verified by the Yggdrasil key on the Yggdrasil network.", cls: "ok" },
  ygg_addr: { name: "Yggdrasil address", label: "verified", tip: "Yggdrasil only accepts this address from its owner.", cls: "ok" },
  ygg_subnet: { name: "Yggdrasil subnet", label: "whole subnet", tip: "That node and everything it routes.", cls: "warn" },
  ip: { name: "IP", label: "IP only", tip: "Matched by source address only; it can be faked on a shared network.", cls: "warn" },
  ip_suffix: { name: "IP suffix", label: "IP only", tip: "Matched by source address within the network prefix; it can be faked.", cls: "warn" },
  wg_key: { name: "WireGuard key", label: "stored, not enforced yet", tip: "Kept for later; no network enforces it yet.", cls: "muted" },
  tor_client_key: { name: "Tor client key", label: "verified by key", tip: "On a Tor network, only a client holding the matching key can reach the onion service.", cls: "ok" },
  tls_spki: { name: "TLS key", label: "stored, not enforced yet", tip: "Kept for later; no network enforces it yet.", cls: "muted" },
};

export function CredentialBadge({ kind }: { kind: CredentialKind }) {
  const info = CREDENTIAL_INFO[kind];
  return (
    <span
      className={`badge reach reach-${info.cls}`}
      title={info.tip}
      tabIndex={0}
      aria-label={`${info.label}. ${info.tip}`}
    >
      {info.label}
    </span>
  );
}
