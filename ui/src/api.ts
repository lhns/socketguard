// Typed wrappers over the Tauri commands (src-tauri/src/main.rs). Types come from the
// daemon's Rust types via ts-rs (see ./generated).
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { ActivityKind } from "./generated/ActivityKind";
import type { ActivityQuery } from "./generated/ActivityQuery";
import type { ActivityRecord } from "./generated/ActivityRecord";
import type { Address } from "./generated/Address";
import type { App } from "./generated/App";
import type { AppDetail } from "./generated/AppDetail";
import type { ApplyRequest } from "./generated/ApplyRequest";
import type { ApplyResponse } from "./generated/ApplyResponse";
import type { ChangeOp } from "./generated/ChangeOp";
import type { ChangesRequest } from "./generated/ChangesRequest";
import type { ChangesResponse } from "./generated/ChangesResponse";
import type { Credential } from "./generated/Credential";
import type { Enforcement } from "./generated/Enforcement";
import type { ExportDocument } from "./generated/ExportDocument";
import type { ExposureResponse } from "./generated/ExposureResponse";
import type { GrantView } from "./generated/GrantView";
import type { LockoutRiskInfo } from "./generated/LockoutRiskInfo";
import type { MoveAppRequest } from "./generated/MoveAppRequest";
import type { Network } from "./generated/Network";
import type { NewBinding } from "./generated/NewBinding";
import type { NewCredential } from "./generated/NewCredential";
import type { NewGrant } from "./generated/NewGrant";
import type { NewGroup } from "./generated/NewGroup";
import type { NewNetwork } from "./generated/NewNetwork";
import type { NewPeer } from "./generated/NewPeer";
import type { NewReservation } from "./generated/NewReservation";
import type { NewTag } from "./generated/NewTag";
import type { ParsedCredential } from "./generated/ParsedCredential";
import type { Peer } from "./generated/Peer";
import type { PeerGroup } from "./generated/PeerGroup";
import type { ReservationView } from "./generated/ReservationView";
import type { ReserveRequest } from "./generated/ReserveRequest";
import type { PortRef } from "./generated/PortRef";
import type { ProtectHostRequest } from "./generated/ProtectHostRequest";
import type { ProtectHostResponse } from "./generated/ProtectHostResponse";
import type { AttachPortGroup } from "./generated/AttachPortGroup";
import type { NewPortGroup } from "./generated/NewPortGroup";
import type { Scope } from "./generated/Scope";
import type { PortGroup } from "./generated/PortGroup";
import type { UpdatePortGroup } from "./generated/UpdatePortGroup";
import type { Settings } from "./generated/Settings";
import type { ShareResponse } from "./generated/ShareResponse";
import type { StatusResponse } from "./generated/StatusResponse";
import type { Tag } from "./generated/Tag";
import type { TagMember } from "./generated/TagMember";
import type { Target } from "./generated/Target";
import type { TorKeyResponse } from "./generated/TorKeyResponse";
import type { NetworkSetup } from "./generated/NetworkSetup";
import type { SetupKind } from "./generated/SetupKind";
import type { UpdateTag } from "./generated/UpdateTag";

export type {
  ActivityKind, ActivityQuery, ActivityRecord, Address, App, AppDetail, ApplyRequest, ApplyResponse,
  ChangeOp, ChangesRequest, ChangesResponse, Credential, Enforcement, ExportDocument, GrantView,
  LockoutRiskInfo, MoveAppRequest, Network, NewBinding, NewCredential, NewGrant, NewGroup, NewNetwork, NewPeer,
  NewReservation, NewTag, ReservationView, ReserveRequest, ParsedCredential, Peer, PeerGroup, PortRef, ProtectHostRequest, ProtectHostResponse,
  AttachPortGroup, NewPortGroup, Scope, PortGroup, UpdatePortGroup,
  Settings, ShareResponse, StatusResponse, Tag, TagMember, Target, TorKeyResponse,
  UpdateTag,
};
export type { NetworkSetup, SetupKind, ExposureResponse };
export type { NetworkExposure } from "./generated/NetworkExposure";
export type { ExposedListener } from "./generated/ExposedListener";
export type { YggdrasilBlock } from "./generated/YggdrasilBlock";
export type { LanCandidate } from "./generated/LanCandidate";
export type { SetupState } from "./generated/SetupState";
export type { SetupStatus } from "./generated/SetupStatus";
export type { InstallOffer } from "./generated/InstallOffer";
export type { AccessOrigin } from "./generated/AccessOrigin";

/** How `run_network_setup` ended: `launched` false means the elevated command did not start
 * (`command` is what to run by hand); `cancelled` is a declined prompt, not an error. */
export interface SetupRun {
  launched: boolean;
  cancelled: boolean;
  exit_code: number | null;
  command: string;
}
export type { PortRange } from "./generated/PortRange";
export type { AddrFamily } from "./generated/AddrFamily";
export type { Binding } from "./generated/Binding";
export type { BindingTarget } from "./generated/BindingTarget";
export type { PortConflict } from "./generated/PortConflict";
export type { Reservation } from "./generated/Reservation";
export type { AppPort } from "./generated/AppPort";
export type { BatchChange } from "./generated/BatchChange";
export type { Change } from "./generated/Change";
export type { EffectiveAccess } from "./generated/EffectiveAccess";
export type { Protocol } from "./generated/Protocol";
export type { Reach } from "./generated/Reach";
export type { CredentialKind } from "./generated/CredentialKind";
export type { Subject } from "./generated/Subject";
export type { GrantReach } from "./generated/GrantReach";
export type { NetworkReach } from "./generated/NetworkReach";
export type { NetworkKind } from "./generated/NetworkKind";
export type { TorShare } from "./generated/TorShare";

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

/** A change's answer: its value, plus the daemon's "saved, not yet enforced" notice after an
 * HTTP 202 (ADR 0042). */
interface Done<T> {
  value: T;
  enforcement: Enforcement | null;
}

const noticeListeners = new Set<(n: Enforcement) => void>();

/** Be told whenever the daemon answers a change with `enforcement: pending`. */
export function onEnforcementNotice(cb: (n: Enforcement) => void): () => void {
  noticeListeners.add(cb);
  return () => {
    noticeListeners.delete(cb);
  };
}

async function callSaved<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const done = await call<Done<T>>(cmd, args);
  if (done.enforcement) for (const cb of noticeListeners) cb(done.enforcement);
  return done.value;
}

export const api = {
  status: () => call<StatusResponse>("status"),
  listApps: () => call<App[]>("list_apps"),
  getApp: (id: string) => call<AppDetail>("get_app", { id }),
  deleteApp: (id: string) => callSaved<null>("delete_app", { id }),
  reviewApp: (id: string, reviewed: boolean) => call<AppDetail>("review_app", { id, reviewed }),
  moveApp: (id: string, req: MoveAppRequest) => callSaved<AppDetail>("move_app", { id, req }),
  shareApp: (id: string) => call<ShareResponse>("share_app", { id }),
  listPeers: () => call<Peer[]>("list_peers"),
  createPeer: (req: NewPeer) => call<Peer>("create_peer", { req }),
  getPeer: (id: string) => call<Peer>("get_peer", { id }),
  updatePeer: (id: string, label: string) => call<Peer>("update_peer", { id, label }),
  deletePeer: (id: string) => callSaved<null>("delete_peer", { id }),
  parseCredentials: (text: string) => call<ParsedCredential[]>("parse_credentials", { text }),
  addCredential: (peerId: string, req: NewCredential) =>
    callSaved<Credential>("add_credential", { peerId, req }),
  removeCredential: (peerId: string, credentialId: string) =>
    callSaved<null>("remove_credential", { peerId, credentialId }),
  generateTorKey: (peerId: string) => callSaved<TorKeyResponse>("generate_tor_key", { peerId }),
  listGroups: () => call<PeerGroup[]>("list_groups"),
  createGroup: (req: NewGroup) => call<PeerGroup>("create_group", { req }),
  updateGroup: (id: string, label: string) => call<PeerGroup>("update_group", { id, label }),
  deleteGroup: (id: string) => callSaved<null>("delete_group", { id }),
  setGroupMembers: (id: string, peerIds: string[]) =>
    callSaved<PeerGroup>("set_group_members", { id, peerIds }),
  listGrants: () => call<GrantView[]>("list_grants"),
  createGrant: (req: NewGrant) => callSaved<GrantView>("create_grant", { req }),
  deleteGrant: (id: string) => callSaved<null>("delete_grant", { id }),
  changes: (req: ChangesRequest) => callSaved<ChangesResponse>("changes", { req }),
  listTags: () => call<Tag[]>("list_tags"),
  createTag: (req: NewTag) => callSaved<Tag>("create_tag", { req }),
  updateTag: (id: string, req: UpdateTag) => callSaved<Tag>("update_tag", { id, req }),
  deleteTag: (id: string) => callSaved<null>("delete_tag", { id }),
  addTagMember: (tagId: string, member: TagMember, confirmOpen = false) =>
    callSaved<Tag>("add_tag_member", { tagId, member, confirmOpen }),
  removeTagMember: (tagId: string, appId: string, scope: Scope) =>
    callSaved<Tag>("remove_tag_member", { tagId, appId, scope }),
  listPortGroups: () => call<PortGroup[]>("list_port_groups"),
  getPortGroup: (id: string) => call<PortGroup>("get_port_group", { id }),
  createPortGroup: (req: NewPortGroup) => callSaved<PortGroup>("create_port_group", { req }),
  updatePortGroup: (id: string, req: UpdatePortGroup) =>
    callSaved<PortGroup>("update_port_group", { id, req }),
  deletePortGroup: (id: string) => callSaved<null>("delete_port_group", { id }),
  attachPortGroup: (id: string, appId: string, req: AttachPortGroup) =>
    callSaved<PortGroup>("attach_port_group", { id, appId, req }),
  detachPortGroup: (id: string, appId: string) =>
    callSaved<PortGroup>("detach_port_group", { id, appId }),
  listNetworks: () => call<Network[]>("list_networks"),
  networkSetup: () => call<NetworkSetup>("network_setup"),
  runNetworkSetup: (kind: SetupKind, config: string) => call<SetupRun>("run_network_setup", { kind, config }),
  openDownloadPage: (url: string) => call<void>("open_download_page", { url }),
  addNetwork: (req: NewNetwork) => callSaved<Network>("add_network", { req }),
  deleteNetwork: (id: string, force: boolean, confirmExposed = false) =>
    call<void>("delete_network", { id, force, confirmExposed }),
  /** What becomes reachable without the block of one network (or all of them): ADR 0051. */
  exposure: (without: string | null) => call<ExposureResponse>("exposure", { without }),
  /** Stop the service that `networks setup` started (elevated); nothing else is undone. */
  stopSetupService: (kind: SetupKind, config: string) => call<SetupRun>("stop_setup_service", { kind, config }),
  listAddresses: () => call<Address[]>("list_addresses"),
  listReservations: () => call<ReservationView[]>("list_reservations"),
  getReservation: (id: string) => call<ReservationView>("get_reservation", { id }),
  createReservation: (req: NewReservation) =>
    callSaved<ReservationView>("create_reservation", { req }),
  renameReservation: (id: string, label: string) =>
    callSaved<ReservationView>("rename_reservation", { id, label }),
  releaseReservation: (id: string) => callSaved<null>("release_reservation", { id }),
  addBinding: (id: string, req: NewBinding) =>
    callSaved<ReservationView>("add_binding", { id, req }),
  removeBinding: (id: string, bindingId: string) =>
    callSaved<ReservationView>("remove_binding", { id, bindingId }),
  reserveAddress: (id: string, req: ReserveRequest) =>
    callSaved<ReservationView>("reserve_address", { id, req }),
  getSettings: () => call<Settings>("get_settings"),
  setProtectHost: (req: ProtectHostRequest) =>
    call<ProtectHostResponse>("set_protect_host", { req }),
  activity: (query: Partial<ActivityQuery>) =>
    call<ActivityRecord[]>("activity", {
      query: { since: null, kind: null, app_id: null, peer_id: null, before: null, limit: null, ...query },
    }),
  exportState: () => call<ExportDocument>("export_state"),
  applyState: (req: ApplyRequest) => call<ApplyResponse>("apply_state", { req }),
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
