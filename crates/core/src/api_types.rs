use serde::{Deserialize, Serialize};

/// Generic API error
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}

/// Response of `GET /api/status`. Phase 6 replaces the HTTP API and extends this.
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub version: String,
}
