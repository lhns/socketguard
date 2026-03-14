use crate::config::{BackendConfig, BackendInstanceConfig, ProcessFilter};
use crate::types::{AclEntry, AclGroup, BackendType, ManagedSocket, Policy, SocketGroup, SocketGroupAddress};
use serde::{Deserialize, Serialize};

/// Response for listing sockets
#[derive(Debug, Serialize, Deserialize)]
pub struct SocketListResponse {
    pub sockets: Vec<ManagedSocket>,
    pub acl_groups: Vec<AclGroupResponse>,
    pub socket_groups: Vec<SocketGroupResponse>,
}

/// Response for a single socket with its ACL
#[derive(Debug, Serialize, Deserialize)]
pub struct SocketDetailResponse {
    pub socket: ManagedSocket,
    pub acl: Vec<AclEntry>,
    pub acl_group_id: Option<String>,
}

/// Request to update an ACL (replace all entries)
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateAclRequest {
    pub entries: Vec<AclEntryInput>,
}

/// Input for creating an ACL entry
#[derive(Debug, Serialize, Deserialize)]
pub struct AclEntryInput {
    pub allowed_ip: String,
    pub label: Option<String>,
}

/// Request to add a single allowed IP
#[derive(Debug, Serialize, Deserialize)]
pub struct AllowIpRequest {
    pub allowed_ip: String,
    pub label: Option<String>,
}

/// Request to update socket policy
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdatePolicyRequest {
    pub policy: Policy,
}

/// Response for config endpoints
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigResponse {
    pub listen_addr: String,
    pub listen_port: u16,
    pub backends: Vec<BackendInstanceConfig>,
    pub poll_interval_secs: u64,
    pub process_filter: ProcessFilter,
}

/// Request to update config
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateConfigRequest {
    pub backends: Option<Vec<BackendInstanceConfig>>,
    pub poll_interval_secs: Option<u64>,
    pub process_filter: Option<ProcessFilter>,
}

/// Available backends response
#[derive(Debug, Serialize, Deserialize)]
pub struct BackendsResponse {
    pub available_types: Vec<BackendInfo>,
    pub active_instances: Vec<BackendInstanceConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackendInfo {
    pub name: BackendType,
    pub description: String,
    pub available: bool,
    pub singleton: bool,
}

/// Request to add a new backend instance
#[derive(Debug, Serialize, Deserialize)]
pub struct AddBackendRequest {
    /// Optional custom ID. If omitted, auto-generated.
    pub id: Option<String>,
    #[serde(flatten)]
    pub backend: BackendConfig,
}

/// Response for listing available network interfaces
#[derive(Debug, Serialize, Deserialize)]
pub struct InterfacesResponse {
    pub interfaces: Vec<String>,
}

/// Generic API error
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}

// --- ACL Group types (ADR 0018) ---

/// Full ACL group response with entries and member socket IDs.
#[derive(Debug, Serialize, Deserialize)]
pub struct AclGroupResponse {
    pub group: AclGroup,
    pub entries: Vec<AclEntry>,
    pub members: Vec<String>,
}

/// Request to create an ACL group.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAclGroupRequest {
    pub label: String,
}

/// Request to update an ACL group.
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateAclGroupRequest {
    pub label: Option<String>,
    pub policy: Option<Policy>,
}

/// Request to add an ACL entry to a group.
#[derive(Debug, Serialize, Deserialize)]
pub struct AddAclGroupEntryRequest {
    pub backend_id: String,
    pub allowed_ip: String,
    pub label: Option<String>,
}

/// Request to add sockets to a group.
#[derive(Debug, Serialize, Deserialize)]
pub struct AddToGroupRequest {
    pub socket_ids: Vec<String>,
}

// --- Socket Group types (ADR 0018) ---

/// Full socket group response with addresses.
#[derive(Debug, Serialize, Deserialize)]
pub struct SocketGroupResponse {
    pub group: SocketGroup,
    pub addresses: Vec<SocketGroupAddress>,
    pub members: Vec<String>,
}

/// Request to create a socket group.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSocketGroupRequest {
    pub label: String,
    pub app_name: String,
}
