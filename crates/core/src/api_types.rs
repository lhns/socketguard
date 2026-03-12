use crate::types::{AclEntry, BackendType, ManagedSocket, Policy};
use serde::{Deserialize, Serialize};

/// Response for listing sockets
#[derive(Debug, Serialize, Deserialize)]
pub struct SocketListResponse {
    pub sockets: Vec<ManagedSocket>,
}

/// Response for a single socket with its ACL
#[derive(Debug, Serialize, Deserialize)]
pub struct SocketDetailResponse {
    pub socket: ManagedSocket,
    pub acl: Vec<AclEntry>,
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
    pub backend: BackendType,
    pub interface: String,
    pub poll_interval_secs: u64,
}

/// Request to update config
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateConfigRequest {
    pub backend: Option<BackendType>,
    pub interface: Option<String>,
    pub poll_interval_secs: Option<u64>,
}

/// Available backends response
#[derive(Debug, Serialize, Deserialize)]
pub struct BackendsResponse {
    pub backends: Vec<BackendInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackendInfo {
    pub name: BackendType,
    pub description: String,
    pub available: bool,
}

/// Generic API error
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}
