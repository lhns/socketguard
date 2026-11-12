//! Typed async client for the SocketGuard local API (ADR 0032, 0033), shared by the CLI and
//! the Tauri backend. It speaks HTTP/1.1 over the platform transport (Unix socket or Windows
//! named pipe), one connection per request, and has one method per route of the API.
//!
//! [`Client::from_env`] takes the endpoint from `SOCKETGUARD_SOCKET` if set, else the
//! platform default ([`default_endpoint`]).

mod routes;
mod sse;
mod transport;

pub use routes::{Route, CLIENT_ROUTES};
pub use socketguard_core::api_types::ApiEvent;
pub use sse::EventStream;

use bytes::Bytes;
use http::{header, HeaderValue, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use serde::{de::DeserializeOwned, Serialize};
use socketguard_core::api_types::{
    ApiError, ApplyRequest, ApplyResponse, AttachPortGroup, ChangesRequest, ChangesResponse,
    DisableRequest, Enforcement, EnforcementNotice, ExportDocument, MemberQuery, MoveAppRequest,
    NewBinding, NewGroup, NewNetwork, NewPeer, NewPortGroup, NewReservation, NewTag, NewTagMember,
    ParseCredentialsRequest, ProtectHostRequest, ProtectHostResponse, ReserveRequest, SetBridges,
    SetMembers, SetPeers, ShareResponse, StatusResponse, TorKeyResponse, UpdateLabel,
    UpdatePortGroup, UpdateTag,
};
use socketguard_core::setup::NetworkSetup;
use socketguard_core::{
    ActivityQuery, ActivityRecord, Address, App, AppDetail, Credential, GrantView, Network,
    NewCredential, NewGrant, ParsedCredential, Peer, PeerGroup, PortGroup, ReservationView, Scope,
    Settings, Tag, TagMember,
};

/// Environment variable that overrides the endpoint (socket path or pipe name).
pub const ENDPOINT_ENV: &str = "SOCKETGUARD_SOCKET";

/// What went wrong with a call.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The daemon could not be reached.
    #[error("cannot reach the daemon at {endpoint}: {source}")]
    Connect {
        endpoint: String,
        source: std::io::Error,
    },
    /// The daemon answered with an error.
    #[error("{message}")]
    Api {
        status: u16,
        code: String,
        message: String,
        details: Option<serde_json::Value>,
    },
    /// The connection broke, or the answer was not what the API promises.
    #[error("protocol error: {0}")]
    Protocol(String),
}

impl Error {
    /// The API error code (`not_found`, `confirmation_required`, ...), if the daemon sent one.
    pub fn code(&self) -> Option<&str> {
        match self {
            Error::Api { code, .. } => Some(code),
            _ => None,
        }
    }

    /// The HTTP status of an API error.
    pub fn status(&self) -> Option<u16> {
        match self {
            Error::Api { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Whether the daemon refused for lack of confirmation.
    pub fn is_confirmation_required(&self) -> bool {
        self.code() == Some(socketguard_core::api_types::error_code::CONFIRMATION_REQUIRED)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// The result of a change that is saved but may not be enforced everywhere yet. The
/// daemon answers 202 then, with `enforcement` saying what is pending (e.g. Tor is down
/// and an onion service could not be taken off the network yet); it keeps retrying.
#[derive(Debug, Clone, PartialEq)]
pub struct Saved<T> {
    pub value: T,
    pub enforcement: Option<Enforcement>,
}

/// Client for one daemon endpoint. Cheap to clone.
#[derive(Clone)]
pub struct Client {
    endpoint: String,
}

/// Filter for [`Client::list_grants`].
#[derive(Debug, Clone, Default, Serialize)]
pub struct GrantQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reservation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

impl Client {
    /// A client for an explicit socket path (Unix) or pipe name (Windows).
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }

    /// The endpoint from `SOCKETGUARD_SOCKET`, else the platform default.
    pub fn from_env() -> Self {
        let from_env = std::env::var(ENDPOINT_ENV).ok();
        Self::new(
            from_env
                .filter(|p| !p.trim().is_empty())
                .unwrap_or_else(default_endpoint),
        )
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    async fn send(
        &self,
        route: &Route,
        params: &[&str],
        query: Option<String>,
        body: Option<Vec<u8>>,
    ) -> Result<hyper::Response<hyper::body::Incoming>> {
        let mut uri = route.fill(params);
        if let Some(q) = query.filter(|q| !q.is_empty()) {
            uri.push('?');
            uri.push_str(&q);
        }
        let mut builder = Request::builder()
            .method(route.method.clone())
            .uri(uri)
            .header(header::HOST, "localhost")
            .header(header::ACCEPT, HeaderValue::from_static("*/*"));
        if body.is_some() {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        let req = builder
            .body(Full::new(Bytes::from(body.unwrap_or_default())))
            .map_err(|e| Error::Protocol(e.to_string()))?;

        let stream = transport::connect(&self.endpoint)
            .await
            .map_err(|source| Error::Connect {
                endpoint: self.endpoint.clone(),
                source,
            })?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| Error::Protocol(e.to_string()))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender
            .send_request(req)
            .await
            .map_err(|e| Error::Protocol(e.to_string()))
    }

    /// Send, check the status and return the body.
    async fn call_raw(
        &self,
        route: &Route,
        params: &[&str],
        query: Option<String>,
        body: Option<Vec<u8>>,
    ) -> Result<Bytes> {
        Ok(self.call_status(route, params, query, body).await?.1)
    }

    /// Like [`Client::call_raw`], with the success status.
    async fn call_status(
        &self,
        route: &Route,
        params: &[&str],
        query: Option<String>,
        body: Option<Vec<u8>>,
    ) -> Result<(StatusCode, Bytes)> {
        let resp = self.send(route, params, query, body).await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(read_error(resp).await);
        }
        let bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| Error::Protocol(e.to_string()))?
            .to_bytes();
        Ok((status, bytes))
    }

    async fn call<T: DeserializeOwned>(
        &self,
        route: &Route,
        params: &[&str],
        query: Option<String>,
        body: Option<Vec<u8>>,
    ) -> Result<T> {
        let bytes = self.call_raw(route, params, query, body).await?;
        serde_json::from_slice(&bytes).map_err(|e| Error::Protocol(format!("bad response: {e}")))
    }

    async fn call_unit(&self, route: &Route, params: &[&str], body: Option<Vec<u8>>) -> Result<()> {
        self.call_raw(route, params, None, body).await.map(|_| ())
    }

    /// A call whose answer may carry a pending-enforcement notice (HTTP 202): the body of
    /// the change with an `enforcement` field, or the notice alone for a delete.
    async fn call_saved<T: DeserializeOwned>(
        &self,
        route: &Route,
        params: &[&str],
        body: Option<Vec<u8>>,
    ) -> Result<Saved<T>> {
        let (status, bytes) = self.call_status(route, params, None, body).await?;
        self.saved_from(status, &bytes)
    }

    /// Read the answer of a change as [`Client::call_saved`] does.
    fn saved_from<T: DeserializeOwned>(
        &self,
        status: StatusCode,
        bytes: &Bytes,
    ) -> Result<Saved<T>> {
        let bad = |e: serde_json::Error| Error::Protocol(format!("bad response: {e}"));
        // An empty body (204) is the unit value.
        let mut doc = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(bytes).map_err(bad)?
        };
        let enforcement = if status == StatusCode::ACCEPTED {
            let notice: EnforcementNotice = serde_json::from_value(doc.clone()).map_err(bad)?;
            // Nothing but the notice: there is no value to read.
            if doc.as_object().is_some_and(|o| o.len() == 1) {
                doc = serde_json::Value::Null;
            }
            Some(notice.enforcement)
        } else {
            None
        };
        let value = serde_json::from_value(doc).map_err(bad)?;
        Ok(Saved { value, enforcement })
    }

    // ─── Status and events ───────────────────────────────────────────────────

    pub async fn status(&self) -> Result<StatusResponse> {
        self.call(&routes::STATUS, &[], None, None).await
    }

    /// Subscribe to the push events. The stream ends when the daemon closes the connection.
    pub async fn events(&self) -> Result<EventStream> {
        let resp = self.send(&routes::EVENTS, &[], None, None).await?;
        if !resp.status().is_success() {
            return Err(read_error(resp).await);
        }
        Ok(sse::stream(resp.into_body()))
    }

    // ─── Apps ────────────────────────────────────────────────────────────────

    pub async fn list_apps(&self) -> Result<Vec<App>> {
        self.call(&routes::LIST_APPS, &[], None, None).await
    }

    pub async fn get_app(&self, id: &str) -> Result<AppDetail> {
        self.call(&routes::GET_APP, &[id], None, None).await
    }

    /// Forget an app. It reappears as a new app the next time it listens.
    pub async fn delete_app(&self, id: &str) -> Result<Saved<()>> {
        self.call_saved(&routes::DELETE_APP, &[id], None).await
    }

    /// Move the grants, tag memberships, addresses and reservation bindings of app `id` to
    /// `req.to`. Needs `confirm_open` where Anyone is among what moves or gains access.
    pub async fn move_app(&self, id: &str, req: &MoveAppRequest) -> Result<Saved<AppDetail>> {
        self.call_saved(&routes::MOVE_APP, &[id], json(req)).await
    }

    /// What the app's granted Tor peers need to connect: their client authorization lines.
    pub async fn share_app(&self, id: &str) -> Result<ShareResponse> {
        self.call(&routes::SHARE_APP, &[id], None, None).await
    }

    // ─── Peers ───────────────────────────────────────────────────────────────

    pub async fn list_peers(&self) -> Result<Vec<Peer>> {
        self.call(&routes::LIST_PEERS, &[], None, None).await
    }

    pub async fn create_peer(&self, req: &NewPeer) -> Result<Peer> {
        self.call(&routes::CREATE_PEER, &[], None, json(req)).await
    }

    /// Classify pasted text: one result per value, with the kind, the canonical value and
    /// where it works, or an error.
    pub async fn parse_credentials(&self, text: &str) -> Result<Vec<ParsedCredential>> {
        let req = ParseCredentialsRequest { text: text.into() };
        self.call(&routes::PARSE_CREDENTIALS, &[], None, json(&req))
            .await
    }

    pub async fn get_peer(&self, id: &str) -> Result<Peer> {
        self.call(&routes::GET_PEER, &[id], None, None).await
    }

    pub async fn update_peer(&self, id: &str, label: &str) -> Result<Peer> {
        let body = json(&UpdateLabel {
            label: label.to_string(),
        });
        self.call(&routes::UPDATE_PEER, &[id], None, body).await
    }

    pub async fn delete_peer(&self, id: &str) -> Result<Saved<()>> {
        self.call_saved(&routes::DELETE_PEER, &[id], None).await
    }

    pub async fn add_credential(
        &self,
        peer_id: &str,
        req: &NewCredential,
    ) -> Result<Saved<Credential>> {
        self.call_saved(&routes::ADD_CREDENTIAL, &[peer_id], json(req))
            .await
    }

    /// Generate a Tor client key for the peer (replacing the one generated before). The
    /// answer holds the private key; `share_app` hands it out later too.
    pub async fn generate_tor_key(&self, peer_id: &str) -> Result<Saved<TorKeyResponse>> {
        self.call_saved(&routes::GENERATE_TOR_KEY, &[peer_id], None)
            .await
    }

    pub async fn remove_credential(&self, peer_id: &str, credential_id: &str) -> Result<Saved<()>> {
        self.call_saved(&routes::REMOVE_CREDENTIAL, &[peer_id, credential_id], None)
            .await
    }

    // ─── Peer groups ─────────────────────────────────────────────────────────

    pub async fn list_groups(&self) -> Result<Vec<PeerGroup>> {
        self.call(&routes::LIST_GROUPS, &[], None, None).await
    }

    pub async fn create_group(&self, req: &NewGroup) -> Result<PeerGroup> {
        self.call(&routes::CREATE_GROUP, &[], None, json(req)).await
    }

    pub async fn get_group(&self, id: &str) -> Result<PeerGroup> {
        self.call(&routes::GET_GROUP, &[id], None, None).await
    }

    pub async fn update_group(&self, id: &str, label: &str) -> Result<PeerGroup> {
        let body = json(&UpdateLabel {
            label: label.to_string(),
        });
        self.call(&routes::UPDATE_GROUP, &[id], None, body).await
    }

    pub async fn delete_group(&self, id: &str) -> Result<Saved<()>> {
        self.call_saved(&routes::DELETE_GROUP, &[id], None).await
    }

    /// Replace a group's members.
    pub async fn set_group_members(
        &self,
        id: &str,
        peer_ids: &[String],
    ) -> Result<Saved<PeerGroup>> {
        let body = json(&SetMembers {
            peer_ids: peer_ids.to_vec(),
        });
        self.call_saved(&routes::SET_GROUP_MEMBERS, &[id], body)
            .await
    }

    // ─── Grants ──────────────────────────────────────────────────────────────

    pub async fn list_grants(&self, filter: &GrantQuery) -> Result<Vec<GrantView>> {
        let q = serde_urlencoded::to_string(filter).ok();
        self.call(&routes::LIST_GRANTS, &[], q, None).await
    }

    /// Create a grant. To Anyone it needs `confirm_open: true`, else the error code is
    /// `confirmation_required`.
    pub async fn create_grant(&self, req: &NewGrant) -> Result<Saved<GrantView>> {
        self.call_saved(&routes::CREATE_GRANT, &[], json(req)).await
    }

    pub async fn delete_grant(&self, id: &str) -> Result<Saved<()>> {
        self.call_saved(&routes::DELETE_GRANT, &[id], None).await
    }

    /// Apply many changes at once: all or nothing, one firewall update (ADR 0045). With
    /// `dry_run` nothing is saved and the answer says what would change. An `AddGrant` to
    /// Anyone needs `confirm_open`, else the whole batch is refused with the code
    /// `confirmation_required`.
    pub async fn changes(&self, req: &ChangesRequest) -> Result<Saved<ChangesResponse>> {
        self.call_saved(&routes::CHANGES, &[], json(req)).await
    }

    // ─── Tags ────────────────────────────────────────────────────────────────

    pub async fn list_tags(&self) -> Result<Vec<Tag>> {
        self.call(&routes::LIST_TAGS, &[], None, None).await
    }

    pub async fn create_tag(&self, req: &NewTag) -> Result<Saved<Tag>> {
        self.call_saved(&routes::CREATE_TAG, &[], json(req)).await
    }

    pub async fn get_tag(&self, id: &str) -> Result<Tag> {
        self.call(&routes::GET_TAG, &[id], None, None).await
    }

    /// Rename a tag and/or replace its patterns.
    pub async fn update_tag(&self, id: &str, req: &UpdateTag) -> Result<Saved<Tag>> {
        self.call_saved(&routes::UPDATE_TAG, &[id], json(req)).await
    }

    pub async fn delete_tag(&self, id: &str) -> Result<Saved<()>> {
        self.call_saved(&routes::DELETE_TAG, &[id], None).await
    }

    /// Add an app (or a port or port group of it) to a tag. A tag with a grant to Anyone
    /// opens the app, so it needs `confirm_open`, else the error code is
    /// `confirmation_required`.
    pub async fn add_tag_member(
        &self,
        tag_id: &str,
        member: &TagMember,
        confirm_open: bool,
    ) -> Result<Saved<Tag>> {
        let body = NewTagMember {
            app_id: member.app_id.clone(),
            scope: member.scope.clone(),
            confirm_open,
        };
        self.call_saved(&routes::ADD_TAG_MEMBER, &[tag_id], json(&body))
            .await
    }

    /// Remove an app (`Scope::All`), or one port or port group of it, from a tag.
    pub async fn remove_tag_member(
        &self,
        tag_id: &str,
        app_id: &str,
        scope: &Scope,
    ) -> Result<Saved<Tag>> {
        let query = match scope {
            Scope::All => MemberQuery::default(),
            Scope::Port { port, proto } => MemberQuery {
                port: Some(*port),
                proto: Some(*proto),
                group: None,
            },
            Scope::Group { id } => MemberQuery {
                group: Some(id.clone()),
                ..MemberQuery::default()
            },
        };
        let q = serde_urlencoded::to_string(&query).ok();
        let (status, bytes) = self
            .call_status(&routes::REMOVE_TAG_MEMBER, &[tag_id, app_id], q, None)
            .await?;
        self.saved_from(status, &bytes)
    }

    // ─── Port groups ───────────────────────────────────────────────────────

    pub async fn list_port_groups(&self) -> Result<Vec<PortGroup>> {
        self.call(&routes::LIST_PORT_GROUPS, &[], None, None).await
    }

    pub async fn get_port_group(&self, id: &str) -> Result<PortGroup> {
        self.call(&routes::GET_PORT_GROUP, &[id], None, None).await
    }

    /// Create a port group (and attach it to `req.apps`). Where attaching would open an
    /// app to Anyone it needs `confirm_open`, else the code is `confirmation_required`.
    pub async fn create_port_group(&self, req: &NewPortGroup) -> Result<Saved<PortGroup>> {
        self.call_saved(&routes::CREATE_PORT_GROUP, &[], json(req))
            .await
    }

    /// Rename a port group and/or replace its ports.
    pub async fn update_port_group(
        &self,
        id: &str,
        req: &UpdatePortGroup,
    ) -> Result<Saved<PortGroup>> {
        self.call_saved(&routes::UPDATE_PORT_GROUP, &[id], json(req))
            .await
    }

    /// Delete a port group; refused (409) while a grant or a tag member uses it.
    pub async fn delete_port_group(&self, id: &str) -> Result<Saved<()>> {
        self.call_saved(&routes::DELETE_PORT_GROUP, &[id], None)
            .await
    }

    /// Attach a port group to an app. It widens what the grants that cover All sockets of the app cover, so
    /// where that reaches Anyone it needs `confirm_open`.
    pub async fn attach_port_group(
        &self,
        id: &str,
        app_id: &str,
        confirm_open: bool,
    ) -> Result<Saved<PortGroup>> {
        self.call_saved(
            &routes::ATTACH_PORT_GROUP,
            &[id, app_id],
            json(&AttachPortGroup { confirm_open }),
        )
        .await
    }

    /// Detach a port group from an app; refused (409) while a grant or a tag member uses
    /// it there.
    pub async fn detach_port_group(&self, id: &str, app_id: &str) -> Result<Saved<PortGroup>> {
        self.call_saved(&routes::DETACH_PORT_GROUP, &[id, app_id], None)
            .await
    }

    // ─── Reservations and addresses ──────────────────────────────────────────

    /// Every address, automatic and reserved, with `up`, `excluded` and Tor `notes`.
    pub async fn list_addresses(&self) -> Result<Vec<Address>> {
        self.call(&routes::LIST_ADDRESSES, &[], None, None).await
    }

    pub async fn list_reservations(&self) -> Result<Vec<ReservationView>> {
        self.call(&routes::LIST_RESERVATIONS, &[], None, None).await
    }

    pub async fn get_reservation(&self, id: &str) -> Result<ReservationView> {
        self.call(&routes::GET_RESERVATION, &[id], None, None).await
    }

    pub async fn create_reservation(&self, req: &NewReservation) -> Result<Saved<ReservationView>> {
        self.call_saved(&routes::CREATE_RESERVATION, &[], json(req))
            .await
    }

    pub async fn rename_reservation(
        &self,
        id: &str,
        label: &str,
    ) -> Result<Saved<ReservationView>> {
        self.call_saved(
            &routes::RENAME_RESERVATION,
            &[id],
            json(&UpdateLabel {
                label: label.to_string(),
            }),
        )
        .await
    }

    /// Delete a reservation, its addresses and the grants on it.
    pub async fn release_reservation(&self, id: &str) -> Result<Saved<()>> {
        self.call_saved(&routes::RELEASE_RESERVATION, &[id], None)
            .await
    }

    /// Bind a row (or a tag) to a reservation. Where a grant to Anyone targets the
    /// reservation it needs `confirm_open`.
    pub async fn add_binding(&self, id: &str, req: &NewBinding) -> Result<Saved<ReservationView>> {
        self.call_saved(&routes::ADD_BINDING, &[id], json(req))
            .await
    }

    pub async fn remove_binding(
        &self,
        id: &str,
        binding_id: &str,
    ) -> Result<Saved<ReservationView>> {
        self.call_saved(&routes::REMOVE_BINDING, &[id, binding_id], None)
            .await
    }

    /// Turn an automatic address into a reservation with that row bound.
    pub async fn reserve_address(
        &self,
        id: &str,
        req: &ReserveRequest,
    ) -> Result<Saved<ReservationView>> {
        self.call_saved(&routes::RESERVE_ADDRESS, &[id], json(req))
            .await
    }

    // ─── Networks ────────────────────────────────────────────────────────────

    pub async fn list_networks(&self) -> Result<Vec<Network>> {
        self.call(&routes::LIST_NETWORKS, &[], None, None).await
    }

    /// What can be added on this host and how far each kind is (ADR 0048).
    pub async fn network_setup(&self) -> Result<NetworkSetup> {
        self.call(&routes::NETWORK_SETUP, &[], None, None).await
    }

    /// Add a network. The answer carries `enforcement` (HTTP 202) when the firewall rules
    /// could not be applied, i.e. the network is not closed yet (ADR 0051).
    pub async fn add_network(&self, req: &NewNetwork) -> Result<Saved<Network>> {
        self.call_saved(&routes::ADD_NETWORK, &[], json(req)).await
    }

    /// Replace the peers of a Yggdrasil network (ADR 0052).
    pub async fn set_peers(&self, id: &str, peers: &[String]) -> Result<Network> {
        let req = SetPeers {
            peers: peers.to_vec(),
        };
        self.call(&routes::SET_PEERS, &[id], None, json(&req)).await
    }

    /// Replace the bridge lines of a Tor network (ADR 0052); Tor restarts.
    pub async fn set_bridges(&self, id: &str, bridges: &[String]) -> Result<Network> {
        let req = SetBridges {
            bridges: bridges.to_vec(),
        };
        self.call(&routes::SET_BRIDGES, &[id], None, json(&req))
            .await
    }

    /// Remove a network. With `force`, a Tor network goes even if its onion services
    /// could not be removed (the daemon otherwise answers 409 `conflict`).
    pub async fn delete_network(&self, id: &str, force: bool) -> Result<()> {
        let query = force.then(|| "force=true".to_string());
        self.call_raw(&routes::DELETE_NETWORK, &[id], query, None)
            .await
            .map(|_| ())
    }

    // ─── Settings ────────────────────────────────────────────────────────────

    pub async fn get_settings(&self) -> Result<Settings> {
        self.call(&routes::GET_SETTINGS, &[], None, None).await
    }

    /// Turn whole-host protection on for `interfaces` (empty list: off). The daemon refuses
    /// with code `protect_host_refused` (details: the risks) unless `force`.
    pub async fn set_protect_host(&self, req: &ProtectHostRequest) -> Result<ProtectHostResponse> {
        self.call(&routes::SET_PROTECT_HOST, &[], None, json(req))
            .await
    }

    // ─── Activity, export, maintenance ───────────────────────────────────────

    pub async fn activity(&self, query: &ActivityQuery) -> Result<Vec<ActivityRecord>> {
        let q = serde_urlencoded::to_string(query).ok();
        self.call(&routes::ACTIVITY, &[], q, None).await
    }

    pub async fn export(&self) -> Result<ExportDocument> {
        self.call(&routes::EXPORT, &[], None, None).await
    }

    /// Diff `req.document` against the daemon's state and, unless `dry_run`, apply it.
    pub async fn apply(&self, req: &ApplyRequest) -> Result<ApplyResponse> {
        self.call(&routes::APPLY, &[], None, json(req)).await
    }

    /// Remove all firewall rules and addresses (needs `confirm`) and keep them off, also
    /// across restarts, until [`Client::enable`].
    pub async fn disable(&self, confirm: bool) -> Result<()> {
        self.call_unit(&routes::DISABLE, &[], json(&DisableRequest { confirm }))
            .await
    }

    /// Clear `disable` and put the rules and addresses back.
    pub async fn enable(&self) -> Result<()> {
        self.call_unit(&routes::ENABLE, &[], None).await
    }

    /// Portable mode only (ADR 0054): end the daemon through its teardown (rules and
    /// addresses removed). The daemon answers first and exits a moment later.
    pub async fn shutdown(&self) -> Result<()> {
        self.call_unit(&routes::SHUTDOWN, &[], None).await
    }
}

fn json<T: Serialize>(v: &T) -> Option<Vec<u8>> {
    // Serializing the API's own types cannot fail.
    serde_json::to_vec(v).ok()
}

/// The error of a response whose status is not a success: its body, read in full.
async fn read_error(resp: hyper::Response<hyper::body::Incoming>) -> Error {
    let status = resp.status();
    match resp.into_body().collect().await {
        Ok(body) => api_error(status, &body.to_bytes()),
        Err(e) => Error::Protocol(e.to_string()),
    }
}

fn api_error(status: StatusCode, body: &[u8]) -> Error {
    match serde_json::from_slice::<ApiError>(body) {
        Ok(e) => Error::Api {
            status: status.as_u16(),
            code: e.code,
            message: e.message,
            details: e.details,
        },
        Err(_) => Error::Api {
            status: status.as_u16(),
            code: "unknown".to_string(),
            message: format!(
                "HTTP {status}: {}",
                String::from_utf8_lossy(body)
                    .chars()
                    .take(200)
                    .collect::<String>()
            ),
            details: None,
        },
    }
}

/// The platform's default endpoint (the daemon's default socket or pipe), whatever the
/// environment says. Portable mode has a pipe of its own.
pub fn default_endpoint() -> String {
    if socketguard_core::portable::is_portable() {
        socketguard_core::portable::API_PIPE.to_string()
    } else if cfg!(windows) {
        socketguard_core::config::DEFAULT_API_PIPE.to_string()
    } else {
        socketguard_core::config::DEFAULT_API_SOCKET.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socketguard_core::{ActivityKind, ActivityQuery};

    #[test]
    fn the_activity_query_is_its_own_query_string() {
        assert_eq!(
            serde_urlencoded::to_string(ActivityQuery::default()).unwrap(),
            ""
        );
        let q = ActivityQuery {
            kind: Some(ActivityKind::Blocked),
            app_id: Some("a 1".into()),
            peer_id: Some("p1".into()),
            before: Some(7),
            limit: Some(50),
            ..Default::default()
        };
        assert_eq!(
            serde_urlencoded::to_string(&q).unwrap(),
            "kind=blocked&app_id=a+1&peer_id=p1&before=7&limit=50"
        );
        // And back: this is what the daemon extracts.
        let back: ActivityQuery =
            serde_urlencoded::from_str("kind=blocked&app_id=a+1&peer_id=p1&before=7&limit=50")
                .unwrap();
        assert_eq!(back, q);
    }

    #[test]
    fn the_endpoint_comes_from_the_environment_or_the_platform_default() {
        // One test: the environment is shared by the threads of the test binary.
        std::env::set_var(ENDPOINT_ENV, "/tmp/custom.sock");
        assert_eq!(Client::from_env().endpoint(), "/tmp/custom.sock");
        std::env::set_var(ENDPOINT_ENV, "  ");
        assert_eq!(Client::from_env().endpoint(), default_endpoint());
        std::env::remove_var(ENDPOINT_ENV);
        assert_eq!(Client::from_env().endpoint(), default_endpoint());
    }
}
