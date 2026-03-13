import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";

export interface SocketAddress {
  backend_id: string;
  backend_type: string;
  address: string;
  interface: string;
  prefix_len: number;
  keypair_id: string | null;
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
}

export interface AclEntry {
  id: number;
  socket_id: string;
  allowed_ip: string;
  label: string | null;
  created_at: string;
}

export interface SocketListResponse {
  sockets: ManagedSocket[];
}

export interface SocketDetailResponse {
  socket: ManagedSocket;
  acl: AclEntry[];
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

export interface ConfigResponse {
  listen_addr: string;
  listen_port: number;
  backends: BackendInstanceConfig[];
  poll_interval_secs: number;
}

export interface UpdateConfigRequest {
  backends?: BackendInstanceConfig[];
  poll_interval_secs?: number;
}

export interface AddBackendRequest {
  id?: string;
  type: string;
  interface: string;
  prefix?: string;
}

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
