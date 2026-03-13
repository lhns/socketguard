import { invoke } from "@tauri-apps/api/core";

export interface ManagedSocket {
  id: string;
  pid: number;
  process_name: string;
  port: number;
  protocol: string;
  assigned_ipv6: string;
  backend: string;
  policy: string;
  keypair_id: string | null;
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

export interface ConfigResponse {
  listen_addr: string;
  listen_port: number;
  backend: string;
  interface: string;
  poll_interval_secs: number;
}

export interface UpdateConfigRequest {
  backend?: string;
  interface?: string;
  poll_interval_secs?: number;
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
