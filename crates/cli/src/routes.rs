//! Which client method, and so which API route, each command uses. The coverage test
//! (tests/coverage.rs) looks the method and path up in the client's `CLIENT_ROUTES`, checks
//! that every route of the daemon's `api::ROUTES` is used here and that every command named
//! here exists, so a route cannot be added without a command (ADR 0033).

pub struct CliRoute {
    /// The subcommand path, e.g. `peers cred add`.
    pub command: &'static str,
    /// The `socketguard_client::Client` method it calls.
    pub client_method: &'static str,
}

const fn r(command: &'static str, client_method: &'static str) -> CliRoute {
    CliRoute {
        command,
        client_method,
    }
}

pub const CLI_ROUTES: &[CliRoute] = &[
    r("status", "status"),
    r("init", "status"),
    r("watch", "events"),
    r("apps list", "list_apps"),
    r("pending", "list_apps"),
    r("apps show", "get_app"),
    r("share", "get_app"),
    r("apps rm", "delete_app"),
    r("apps review", "review_app"),
    r("pending", "review_app"),
    r("apps split", "split_app"),
    r("apps merge", "merge_app"),
    r("peers list", "list_peers"),
    r("peers add", "create_peer"),
    r("peers show", "get_peer"),
    r("peers rename", "update_peer"),
    r("peers rm", "delete_peer"),
    r("peers cred add", "add_credential"),
    r("peers cred rm", "remove_credential"),
    r("groups list", "list_groups"),
    r("groups add", "create_group"),
    r("groups show", "get_group"),
    r("groups rename", "update_group"),
    r("groups rm", "delete_group"),
    r("groups members", "set_group_members"),
    r("grants", "list_grants"),
    r("grant", "create_grant"),
    r("pending", "create_grant"),
    r("revoke", "delete_grant"),
    r("networks list", "list_networks"),
    r("networks add", "add_network"),
    r("init", "add_network"),
    r("networks rm", "delete_network"),
    r("settings show", "get_settings"),
    r("protect-host status", "get_settings"),
    r("settings address-mode", "update_settings"),
    r("protect-host on", "set_protect_host"),
    r("protect-host off", "set_protect_host"),
    r("activity", "activity"),
    r("export", "export"),
    r("apply", "apply"),
    r("disable", "disable"),
    r("enable", "enable"),
];
