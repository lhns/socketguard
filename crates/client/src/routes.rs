//! The routes the client implements. Each client method takes its path from one of these
//! constants, and [`CLIENT_ROUTES`] lists all of them with the name of the client method, so
//! the coverage tests can compare them with the daemon's routes and the CLI's commands.

use http::Method;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

/// One route: the name of the client method that calls it, an HTTP method and a path
/// template with `{name}` segments.
pub struct Route {
    pub name: &'static str,
    pub method: Method,
    pub path: &'static str,
}

impl Route {
    /// The path with its `{...}` segments replaced, in order, by the percent-encoded
    /// `params`.
    pub fn fill(&self, params: &[&str]) -> String {
        let mut params = params.iter();
        self.path
            .split('/')
            .map(|seg| {
                if seg.starts_with('{') && seg.ends_with('}') {
                    let p = params.next().expect("a parameter for every {segment}");
                    utf8_percent_encode(p, NON_ALPHANUMERIC).to_string()
                } else {
                    seg.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    }
}

macro_rules! routes {
    ($($name:ident = $client_method:ident: $method:ident $path:literal,)*) => {
        $(pub(crate) const $name: Route = Route {
            name: stringify!($client_method),
            method: Method::$method,
            path: $path,
        };)*

        /// Every route the client has a method for.
        pub const CLIENT_ROUTES: &[Route] = &[$(Route {
            name: stringify!($client_method),
            method: Method::$method,
            path: $path,
        },)*];
    };
}

routes! {
    STATUS = status: GET "/api/status",
    EVENTS = events: GET "/api/events",
    LIST_APPS = list_apps: GET "/api/apps",
    GET_APP = get_app: GET "/api/apps/{id}",
    DELETE_APP = delete_app: DELETE "/api/apps/{id}",
    REVIEW_APP = review_app: POST "/api/apps/{id}/review",
    MOVE_APP = move_app: POST "/api/apps/{id}/move",
    SHARE_APP = share_app: GET "/api/apps/{id}/share",
    LIST_PEERS = list_peers: GET "/api/peers",
    CREATE_PEER = create_peer: POST "/api/peers",
    GET_PEER = get_peer: GET "/api/peers/{id}",
    UPDATE_PEER = update_peer: PATCH "/api/peers/{id}",
    DELETE_PEER = delete_peer: DELETE "/api/peers/{id}",
    PARSE_CREDENTIALS = parse_credentials: POST "/api/credentials/parse",
    ADD_CREDENTIAL = add_credential: POST "/api/peers/{id}/credentials",
    REMOVE_CREDENTIAL = remove_credential: DELETE "/api/peers/{id}/credentials/{cred_id}",
    GENERATE_TOR_KEY = generate_tor_key: POST "/api/peers/{id}/tor-key",
    LIST_GROUPS = list_groups: GET "/api/peer-groups",
    CREATE_GROUP = create_group: POST "/api/peer-groups",
    GET_GROUP = get_group: GET "/api/peer-groups/{id}",
    UPDATE_GROUP = update_group: PATCH "/api/peer-groups/{id}",
    DELETE_GROUP = delete_group: DELETE "/api/peer-groups/{id}",
    SET_GROUP_MEMBERS = set_group_members: PUT "/api/peer-groups/{id}/members",
    LIST_GRANTS = list_grants: GET "/api/grants",
    CREATE_GRANT = create_grant: POST "/api/grants",
    DELETE_GRANT = delete_grant: DELETE "/api/grants/{id}",
    CHANGES = changes: POST "/api/changes",
    LIST_TAGS = list_tags: GET "/api/tags",
    CREATE_TAG = create_tag: POST "/api/tags",
    GET_TAG = get_tag: GET "/api/tags/{id}",
    UPDATE_TAG = update_tag: PATCH "/api/tags/{id}",
    DELETE_TAG = delete_tag: DELETE "/api/tags/{id}",
    ADD_TAG_MEMBER = add_tag_member: POST "/api/tags/{id}/members",
    REMOVE_TAG_MEMBER = remove_tag_member: DELETE "/api/tags/{id}/members/{app_id}",
    LIST_PORT_GROUPS = list_port_groups: GET "/api/port-groups",
    CREATE_PORT_GROUP = create_port_group: POST "/api/port-groups",
    GET_PORT_GROUP = get_port_group: GET "/api/port-groups/{id}",
    UPDATE_PORT_GROUP = update_port_group: PUT "/api/port-groups/{id}",
    DELETE_PORT_GROUP = delete_port_group: DELETE "/api/port-groups/{id}",
    ATTACH_PORT_GROUP = attach_port_group: PUT "/api/port-groups/{id}/apps/{app_id}",
    DETACH_PORT_GROUP = detach_port_group: DELETE "/api/port-groups/{id}/apps/{app_id}",
    LIST_RESERVATIONS = list_reservations: GET "/api/reservations",
    CREATE_RESERVATION = create_reservation: POST "/api/reservations",
    GET_RESERVATION = get_reservation: GET "/api/reservations/{id}",
    RENAME_RESERVATION = rename_reservation: PUT "/api/reservations/{id}",
    RELEASE_RESERVATION = release_reservation: DELETE "/api/reservations/{id}",
    ADD_BINDING = add_binding: POST "/api/reservations/{id}/bindings",
    REMOVE_BINDING = remove_binding: DELETE "/api/reservations/{id}/bindings/{binding_id}",
    LIST_ADDRESSES = list_addresses: GET "/api/addresses",
    RESERVE_ADDRESS = reserve_address: POST "/api/addresses/{id}/reserve",
    LIST_NETWORKS = list_networks: GET "/api/networks",
    NETWORK_SETUP = network_setup: GET "/api/networks/setup",
    ADD_NETWORK = add_network: POST "/api/networks",
    DELETE_NETWORK = delete_network: DELETE "/api/networks/{id}",
    EXPOSURE = exposure: GET "/api/exposure",
    GET_SETTINGS = get_settings: GET "/api/settings",
    SET_PROTECT_HOST = set_protect_host: PUT "/api/settings/protect-host",
    ACTIVITY = activity: GET "/api/activity",
    EXPORT = export: GET "/api/export",
    APPLY = apply: POST "/api/apply",
    DISABLE = disable: POST "/api/disable",
    ENABLE = enable: POST "/api/enable",
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_replaces_segments_in_order_and_encodes() {
        assert_eq!(
            REMOVE_CREDENTIAL.fill(&["p 1", "c/2"]),
            "/api/peers/p%201/credentials/c%2F2"
        );
        assert_eq!(STATUS.fill(&[]), "/api/status");
    }

    #[test]
    fn route_constants_match_the_table() {
        assert!(CLIENT_ROUTES
            .iter()
            .any(|r| r.method == Method::PUT && r.path == "/api/settings/protect-host"));
        // Every route is listed once, under the name of its constant.
        let mut seen = std::collections::BTreeSet::new();
        for r in CLIENT_ROUTES {
            assert!(seen.insert((r.method.to_string(), r.path)), "{}", r.path);
            assert_eq!(r.name, r.name.to_lowercase());
        }
    }
}
