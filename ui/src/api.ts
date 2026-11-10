// Typed wrappers over the Tauri commands (src-tauri/src/main.rs). Types come from the
// daemon's Rust types via ts-rs (see ./generated).
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { ActivityKind } from "./generated/ActivityKind";
import type { ActivityQuery } from "./generated/ActivityQuery";
import type { ActivityRecord } from "./generated/ActivityRecord";
import type { App } from "./generated/App";
import type { AppDetail } from "./generated/AppDetail";
import type { Credential } from "./generated/Credential";
import type { GrantView } from "./generated/GrantView";
import type { LockoutRiskInfo } from "./generated/LockoutRiskInfo";
import type { Network } from "./generated/Network";
import type { NewCredential } from "./generated/NewCredential";
import type { NewGrant } from "./generated/NewGrant";
import type { NewPeer } from "./generated/NewPeer";
import type { Peer } from "./generated/Peer";
import type { PeerGroup } from "./generated/PeerGroup";
import type { ProtectHostRequest } from "./generated/ProtectHostRequest";
import type { ProtectHostResponse } from "./generated/ProtectHostResponse";
import type { Settings } from "./generated/Settings";
import type { StatusResponse } from "./generated/StatusResponse";

export type {
  ActivityKind, ActivityQuery, ActivityRecord, App, AppDetail, Credential, GrantView,
  LockoutRiskInfo, Network, NewCredential, NewGrant, NewPeer, Peer, PeerGroup,
  ProtectHostRequest, ProtectHostResponse, Settings, StatusResponse,
};
export type { Reach } from "./generated/Reach";
export type { CredentialKind } from "./generated/CredentialKind";
export type { Subject } from "./generated/Subject";
export type { GrantReach } from "./generated/GrantReach";

/** Error from a command: the daemon's `{code, message, details}` or a `connection` error. */
export class DaemonError extends Error {
  code: string;
  details: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.code = code;
    this.details = details;
  }
}

export function toDaemonError(e: unknown): DaemonError {
  if (e instanceof DaemonError) return e;
  if (e && typeof e === "object" && "code" in e && "message" in e) {
    const o = e as { code: string; message: string; details?: unknown };
    return new DaemonError(o.code, o.message, o.details ?? undefined);
  }
  return new DaemonError("unknown", String(e));
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (e) {
    throw toDaemonError(e);
  }
}

export const api = {
  status: () => call<StatusResponse>("status"),
  listApps: () => call<App[]>("list_apps"),
  getApp: (id: string) => call<AppDetail>("get_app", { id }),
  reviewApp: (id: string, reviewed: boolean) => call<AppDetail>("review_app", { id, reviewed }),
  listPeers: () => call<Peer[]>("list_peers"),
  createPeer: (req: NewPeer) => call<Peer>("create_peer", { req }),
  addCredential: (peerId: string, req: NewCredential) =>
    call<Credential>("add_credential", { peerId, req }),
  removeCredential: (peerId: string, credentialId: string) =>
    call<void>("remove_credential", { peerId, credentialId }),
  deletePeer: (id: string) => call<void>("delete_peer", { id }),
  listGroups: () => call<PeerGroup[]>("list_groups"),
  listGrants: () => call<GrantView[]>("list_grants"),
  createGrant: (req: NewGrant) => call<GrantView>("create_grant", { req }),
  deleteGrant: (id: string) => call<void>("delete_grant", { id }),
  listNetworks: () => call<Network[]>("list_networks"),
  getSettings: () => call<Settings>("get_settings"),
  setProtectHost: (req: ProtectHostRequest) =>
    call<ProtectHostResponse>("set_protect_host", { req }),
  activity: (query: Partial<ActivityQuery>) =>
    call<ActivityRecord[]>("activity", {
      query: { since: null, kind: null, app_id: null, peer_id: null, before: null, limit: null, ...query },
    }),
  enable: () => call<void>("enable"),
  disable: () => call<void>("disable", { confirm: true }),
  startDaemon: () => call<void>("start_daemon"),
  subscribeEvents: () => call<void>("subscribe_events"),
};

/** Subscribe to a daemon event re-emitted by the Tauri backend (same names as the SSE events, plus
 * the UI-local `daemon_connected` / `daemon_disconnected`). */
export function onDaemonEvent(name: string, cb: () => void): Promise<UnlistenFn> {
  return listen(name, () => cb());
}
