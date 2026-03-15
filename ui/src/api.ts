import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";

export interface SocketAddress {
  backend_id: string;
  backend_type: string;
  address: string;
  interface: string;
  prefix_len: number;
  keypair_id: string | null;
  policy: string;
}

export interface ManagedSocket {
  id: string;
  pid: number;
  process_name: string;
  port: number;
  protocol: string;
  addresses: SocketAddress[];
  policy: string;
  exe_path: string | null;
  cmdline: string | null;
  first_seen: string;
  last_seen: string;
  acl_group_id?: string | null;
  socket_group_ids: string[];
}

export interface AclEntry {
  id: number;
  socket_id: string;
  backend_id: string;
  allowed_ip: string;
  label: string | null;
  created_at: string;
}

// ACL Group types (ADR 0018)
export interface AclGroup {
  id: string;
  label: string;
  policy: string;
  created_at: string;
}

export interface AclGroupResponse {
  group: AclGroup;
  entries: AclEntry[];
  members: string[];
}

// Socket Group types (ADR 0018)
export interface SocketGroup {
  id: string;
  label: string;
  app_name: string;
  created_at: string;
}

export interface SocketGroupAddress {
  group_id: string;
  backend_id: string;
  address: string;
  interface: string;
  prefix_len: number;
  keypair_id: string | null;
  policy: string;
}

export interface SocketGroupAclEntry {
  id: number;
  group_id: string;
  backend_id: string;
  allowed_ip: string;
  label: string | null;
  created_at: string;
}

export interface SocketGroupResponse {
  group: SocketGroup;
  addresses: SocketGroupAddress[];
  members: string[];
  acl_entries: SocketGroupAclEntry[];
  acl_group_id?: string | null;
}

export interface SocketListResponse {
  sockets: ManagedSocket[];
  acl_groups: AclGroupResponse[];
  socket_groups: SocketGroupResponse[];
}

export interface SocketDetailResponse {
  socket: ManagedSocket;
  acl: AclEntry[];
  acl_group_id: string | null;
}

export type BackendConfig =
  | { type: "ula"; interface: string }
  | { type: "yggdrasil"; interface: string }
  | { type: "slaac"; interface: string; prefix?: string }
  | { type: "dhcpv6"; interface: string };

export interface BackendInstanceConfig {
  id: string;
  type: string;
  interface: string;
  prefix?: string;
}

export interface BackendInfo {
  name: string;
  description: string;
  available: boolean;
  singleton: boolean;
}

export interface BackendsResponse {
  available_types: BackendInfo[];
  active_instances: BackendInstanceConfig[];
}

export interface ProcessFilter {
  mode: "allowlist" | "denylist";
  patterns: string[];
}

export interface ConfigResponse {
  listen_addr: string;
  listen_port: number;
  backends: BackendInstanceConfig[];
  poll_interval_secs: number;
  process_filter: ProcessFilter;
}

export interface UpdateConfigRequest {
  backends?: BackendInstanceConfig[];
  poll_interval_secs?: number;
  process_filter?: ProcessFilter;
}

export interface AddBackendRequest {
  id?: string;
  type: string;
  interface: string;
  prefix?: string;
}

// ======== Socket functions ========

export async function listSockets(): Promise<SocketListResponse> {
  return invoke("list_sockets");
}

export async function getSocket(id: string): Promise<SocketDetailResponse> {
  return invoke("get_socket", { id });
}

export async function allowIp(
  socketId: string,
  ip: string,
  label?: string
): Promise<void> {
  return invoke("allow_ip", { socketId, ip, label });
}

export async function removeAclEntry(
  socketId: string,
  entryId: number
): Promise<void> {
  return invoke("remove_acl_entry", { socketId, entryId });
}

export async function setPolicy(
  socketId: string,
  policy: string
): Promise<void> {
  return invoke("set_policy", { socketId, policy });
}

export async function setBackendPolicy(
  socketId: string,
  backendId: string,
  policy: string
): Promise<void> {
  return invoke("set_backend_policy", { socketId, backendId, policy });
}

export async function allowBackendIp(
  socketId: string,
  backendId: string,
  ip: string,
  label?: string
): Promise<void> {
  return invoke("allow_backend_ip", { socketId, backendId, ip, label });
}

// ======== ACL Group functions (ADR 0018) ========

export async function listAclGroups(): Promise<AclGroupResponse[]> {
  return invoke("list_acl_groups");
}

export async function createAclGroup(label: string): Promise<AclGroupResponse> {
  return invoke("create_acl_group", { label });
}

export async function getAclGroup(id: string): Promise<AclGroupResponse> {
  return invoke("get_acl_group", { id });
}

export async function updateAclGroup(
  id: string,
  label?: string,
  policy?: string
): Promise<void> {
  return invoke("update_acl_group", { id, label, policy });
}

export async function deleteAclGroup(id: string): Promise<void> {
  return invoke("delete_acl_group", { id });
}

export async function addToAclGroup(
  groupId: string,
  socketIds: string[]
): Promise<void> {
  return invoke("add_to_acl_group", { groupId, socketIds });
}

export async function removeFromAclGroup(
  groupId: string,
  socketId: string
): Promise<void> {
  return invoke("remove_from_acl_group", { groupId, socketId });
}

export async function addAclGroupEntry(
  groupId: string,
  backendId: string,
  ip: string,
  label?: string
): Promise<void> {
  return invoke("add_acl_group_entry", { groupId, backendId, ip, label });
}

export async function removeAclGroupEntry(
  groupId: string,
  entryId: number
): Promise<void> {
  return invoke("remove_acl_group_entry", { groupId, entryId });
}

// ======== Socket Group functions (ADR 0018) ========

export async function listSocketGroups(): Promise<SocketGroupResponse[]> {
  return invoke("list_socket_groups");
}

export async function createSocketGroup(
  label: string,
  appName: string
): Promise<SocketGroupResponse> {
  return invoke("create_socket_group", { label, appName });
}

export async function updateSocketGroup(
  id: string,
  label: string
): Promise<void> {
  return invoke("update_socket_group", { id, label });
}

export async function deleteSocketGroup(id: string): Promise<void> {
  return invoke("delete_socket_group", { id });
}

export async function addSocketToSocketGroup(
  groupId: string,
  socketIds: string[]
): Promise<void> {
  return invoke("add_socket_to_socket_group", { groupId, socketIds });
}

export async function removeSocketFromSocketGroup(
  groupId: string,
  socketId: string
): Promise<void> {
  return invoke("remove_socket_from_socket_group", { groupId, socketId });
}

export async function setSocketGroupAddressPolicy(
  groupId: string,
  backendId: string,
  policy: string
): Promise<void> {
  return invoke("set_socket_group_address_policy", { groupId, backendId, policy });
}

export async function addSocketGroupAclEntry(
  groupId: string,
  backendId: string,
  ip: string,
  label?: string
): Promise<void> {
  return invoke("add_socket_group_acl_entry", { groupId, backendId, ip, label });
}

export async function removeSocketGroupAclEntry(
  groupId: string,
  entryId: number
): Promise<void> {
  return invoke("remove_socket_group_acl_entry", { groupId, entryId });
}

export async function setSocketGroupAclGroup(
  groupId: string,
  aclGroupId: string | null
): Promise<void> {
  return invoke("set_socket_group_acl_group", { groupId, aclGroupId });
}

// ======== Config functions ========

export async function getConfig(): Promise<ConfigResponse> {
  return invoke("get_config");
}

export async function updateConfig(config: UpdateConfigRequest): Promise<void> {
  return invoke("update_config", { config });
}

export interface InterfacesResponse {
  interfaces: string[];
}

export async function listInterfaces(): Promise<InterfacesResponse> {
  return invoke("list_interfaces");
}

export async function listBackendInstances(): Promise<BackendsResponse> {
  return invoke("list_backend_instances");
}

export async function addBackend(req: AddBackendRequest): Promise<BackendInstanceConfig> {
  return invoke("add_backend", { req });
}

export async function removeBackend(id: string): Promise<void> {
  return invoke("remove_backend", { id });
}

// ======== Events ========

export function onSocketsChanged(callback: () => void): Promise<UnlistenFn> {
  return listen("sockets_changed", callback);
}

export function onConfigChanged(callback: () => void): Promise<UnlistenFn> {
  return listen("config_changed", callback);
}

export function onDaemonConnected(callback: () => void): Promise<UnlistenFn> {
  return listen("daemon_connected", callback);
}

export function onDaemonDisconnected(callback: () => void): Promise<UnlistenFn> {
  return listen("daemon_disconnected", callback);
}

export async function initSSE(): Promise<void> {
  return invoke("subscribe_events");
}

export async function startDaemon(): Promise<void> {
  return invoke("start_daemon");
}
