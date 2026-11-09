//! The routes the client implements. Each client method takes its path from one of these
//! constants, and [`CLIENT_ROUTES`] lists all of them, so the daemon's coverage test can
//! compare the two tables.

use http::Method;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

/// One route: an HTTP method and a path template with `{name}` segments.
pub struct Route {
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
    ($($name:ident: $method:ident $path:literal,)*) => {
        $(pub(crate) const $name: Route = Route { method: Method::$method, path: $path };)*

        /// Every route the client has a method for.
        pub const CLIENT_ROUTES: &[(Method, &str)] = &[$((Method::$method, $path),)*];
    };
}

routes! {
    STATUS: GET "/api/status",
    EVENTS: GET "/api/events",
    LIST_APPS: GET "/api/apps",
    GET_APP: GET "/api/apps/{id}",
    DELETE_APP: DELETE "/api/apps/{id}",
    REVIEW_APP: POST "/api/apps/{id}/review",
    SPLIT_APP: POST "/api/apps/{id}/split",
    MERGE_APP: POST "/api/apps/{id}/merge",
    LIST_PEERS: GET "/api/peers",
    CREATE_PEER: POST "/api/peers",
    GET_PEER: GET "/api/peers/{id}",
    UPDATE_PEER: PATCH "/api/peers/{id}",
    DELETE_PEER: DELETE "/api/peers/{id}",
    ADD_CREDENTIAL: POST "/api/peers/{id}/credentials",
    REMOVE_CREDENTIAL: DELETE "/api/peers/{id}/credentials/{cred_id}",
    LIST_GROUPS: GET "/api/peer-groups",
    CREATE_GROUP: POST "/api/peer-groups",
    GET_GROUP: GET "/api/peer-groups/{id}",
    UPDATE_GROUP: PATCH "/api/peer-groups/{id}",
    DELETE_GROUP: DELETE "/api/peer-groups/{id}",
    SET_GROUP_MEMBERS: PUT "/api/peer-groups/{id}/members",
    LIST_GRANTS: GET "/api/grants",
    CREATE_GRANT: POST "/api/grants",
    DELETE_GRANT: DELETE "/api/grants/{id}",
    LIST_NETWORKS: GET "/api/networks",
    ADD_NETWORK: POST "/api/networks",
    DELETE_NETWORK: DELETE "/api/networks/{id}",
    GET_SETTINGS: GET "/api/settings",
    UPDATE_SETTINGS: PUT "/api/settings",
    SET_PROTECT_HOST: PUT "/api/settings/protect-host",
    ACTIVITY: GET "/api/activity",
    EXPORT: GET "/api/export",
    APPLY: POST "/api/apply",
    DISABLE: POST "/api/disable",
    ENABLE: POST "/api/enable",
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
        assert_eq!(CLIENT_ROUTES.len(), 35);
        assert!(CLIENT_ROUTES
            .iter()
            .any(|(m, p)| *m == Method::PUT && *p == "/api/settings/protect-host"));
    }
}
