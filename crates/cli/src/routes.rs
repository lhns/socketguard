//! Which client method, and so which API route, each command uses. The coverage test
//! (tests/coverage.rs) checks that every route of the daemon's `api::ROUTES` appears here
//! and that every command named here exists, so a route cannot be added without a command
//! (ADR 0033).

pub struct CliRoute {
    /// The subcommand path, e.g. `peers cred add`.
    pub command: &'static str,
    /// The `socketguard_client::Client` method it calls.
    pub client_method: &'static str,
    pub http_method: &'static str,
    pub path: &'static str,
}

const fn r(
    command: &'static str,
    client_method: &'static str,
    http_method: &'static str,
    path: &'static str,
) -> CliRoute {
    CliRoute {
        command,
        client_method,
        http_method,
        path,
    }
}

pub const CLI_ROUTES: &[CliRoute] = &[
    r("status", "status", "GET", "/api/status"),
    r("init", "status", "GET", "/api/status"),
    r("watch", "events", "GET", "/api/events"),
    r("apps list", "list_apps", "GET", "/api/apps"),
    r("pending", "list_apps", "GET", "/api/apps"),
    r("apps show", "get_app", "GET", "/api/apps/{id}"),
    r("share", "get_app", "GET", "/api/apps/{id}"),
    r("apps rm", "delete_app", "DELETE", "/api/apps/{id}"),
    r("apps review", "review_app", "POST", "/api/apps/{id}/review"),
    r("pending", "review_app", "POST", "/api/apps/{id}/review"),
    r("apps split", "split_app", "POST", "/api/apps/{id}/split"),
    r("apps merge", "merge_app", "POST", "/api/apps/{id}/merge"),
    r("peers list", "list_peers", "GET", "/api/peers"),
    r("peers add", "create_peer", "POST", "/api/peers"),
    r("peers show", "get_peer", "GET", "/api/peers/{id}"),
    r("peers rename", "update_peer", "PATCH", "/api/peers/{id}"),
    r("peers rm", "delete_peer", "DELETE", "/api/peers/{id}"),
    r(
        "peers cred add",
        "add_credential",
        "POST",
        "/api/peers/{id}/credentials",
    ),
    r(
        "peers cred rm",
        "remove_credential",
        "DELETE",
        "/api/peers/{id}/credentials/{cred_id}",
    ),
    r("groups list", "list_groups", "GET", "/api/peer-groups"),
    r("groups add", "create_group", "POST", "/api/peer-groups"),
    r("groups show", "get_group", "GET", "/api/peer-groups/{id}"),
    r(
        "groups rename",
        "update_group",
        "PATCH",
        "/api/peer-groups/{id}",
    ),
    r(
        "groups rm",
        "delete_group",
        "DELETE",
        "/api/peer-groups/{id}",
    ),
    r(
        "groups members",
        "set_group_members",
        "PUT",
        "/api/peer-groups/{id}/members",
    ),
    r("grants", "list_grants", "GET", "/api/grants"),
    r("grant", "create_grant", "POST", "/api/grants"),
    r("pending", "create_grant", "POST", "/api/grants"),
    r("revoke", "delete_grant", "DELETE", "/api/grants/{id}"),
    r("networks list", "list_networks", "GET", "/api/networks"),
    r("networks add", "add_network", "POST", "/api/networks"),
    r("init", "add_network", "POST", "/api/networks"),
    r(
        "networks rm",
        "delete_network",
        "DELETE",
        "/api/networks/{id}",
    ),
    r("settings show", "get_settings", "GET", "/api/settings"),
    r(
        "protect-host status",
        "get_settings",
        "GET",
        "/api/settings",
    ),
    r(
        "settings address-mode",
        "update_settings",
        "PUT",
        "/api/settings",
    ),
    r(
        "protect-host on",
        "set_protect_host",
        "PUT",
        "/api/settings/protect-host",
    ),
    r(
        "protect-host off",
        "set_protect_host",
        "PUT",
        "/api/settings/protect-host",
    ),
    r("activity", "activity", "GET", "/api/activity"),
    r("export", "export", "GET", "/api/export"),
    r("apply", "apply", "POST", "/api/apply"),
    r("disable", "disable", "POST", "/api/disable"),
    r("enable", "enable", "POST", "/api/enable"),
];
