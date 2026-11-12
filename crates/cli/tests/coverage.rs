//! Every API route is reachable from a CLI command (ADR 0033), and the table names only
//! commands that exist. The CLI table names client methods; their routes come from the
//! client's `CLIENT_ROUTES`, which the daemon's tests compare with the daemon's routes.

use clap::CommandFactory;
use socketguard_cli::{cli::Cli, CLI_ROUTES};
use socketguard_client::CLIENT_ROUTES;
use socketguard_daemon::api::ROUTES;
use std::collections::BTreeSet;

/// The (method, path) of the client method a CLI command calls.
fn route_of(client_method: &str) -> Option<(String, String)> {
    CLIENT_ROUTES
        .iter()
        .find(|r| r.name == client_method)
        .map(|r| (r.method.to_string(), r.path.to_string()))
}

#[test]
fn every_route_is_reachable_from_a_cli_command() {
    let api: BTreeSet<(String, String)> = ROUTES
        .iter()
        .map(|(m, p)| (m.to_string(), p.to_string()))
        .collect();
    let cli: BTreeSet<(String, String)> = CLI_ROUTES
        .iter()
        .filter_map(|r| route_of(r.client_method))
        .collect();
    let missing: Vec<_> = api.difference(&cli).collect();
    let extra: Vec<_> = cli.difference(&api).collect();
    assert!(
        missing.is_empty(),
        "routes without a CLI command: {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "CLI table names unknown routes: {extra:?}"
    );
}

#[test]
fn the_client_has_every_method_the_table_names() {
    for r in CLI_ROUTES {
        assert!(
            route_of(r.client_method).is_some(),
            "{} uses {} which the client does not have",
            r.command,
            r.client_method
        );
    }
}

#[test]
fn every_command_in_the_table_exists() {
    let root = Cli::command();
    for r in CLI_ROUTES {
        let mut cmd = &root;
        for word in r.command.split(' ') {
            cmd = cmd
                .find_subcommand(word)
                .unwrap_or_else(|| panic!("command {:?} does not exist", r.command));
        }
    }
}

// ─── The desktop UI covers the whole API too (ADR 0042) ──────────────────────────────

/// The Tauri backend's source. The UI crate is not part of this test build (it needs the
/// system webview libraries), so its commands are read as text.
const UI_COMMANDS: &str = include_str!("../../../ui/src-tauri/src/main.rs");

/// CLI commands that deliberately have no UI counterpart: shell completion is meaningless in
/// a window, and `watch` prints the event stream, which the UI consumes through its own bridge.
/// Pinned: adding to it needs a decision, not an edit of the route table.
///
/// `access allow|deny|list` hand over to `socketguard-daemon access` (administrator only,
/// ADR 0050); the UI runs the same daemon command through its own elevation command.
const CLI_ONLY: &[&str] = &[
    "completions",
    "watch",
    "access allow",
    "access deny",
    "access list",
];

#[test]
fn the_cli_only_list_is_pinned() {
    assert_eq!(
        CLI_ONLY,
        [
            "completions",
            "watch",
            "access allow",
            "access deny",
            "access list"
        ]
    );
    let root = Cli::command();
    for name in CLI_ONLY {
        let mut cmd = &root;
        for word in name.split(' ') {
            cmd = cmd
                .find_subcommand(word)
                .unwrap_or_else(|| panic!("CLI-only command {name:?} does not exist"));
        }
    }
}

#[test]
fn every_route_has_a_tauri_command_unless_only_cli_only_commands_use_it() {
    let source: String = UI_COMMANDS.split_whitespace().collect();
    let mut missing = Vec::new();
    for route in CLIENT_ROUTES {
        let users: Vec<&str> = CLI_ROUTES
            .iter()
            .filter(|r| r.client_method == route.name)
            .map(|r| r.command)
            .collect();
        if !users.is_empty() && users.iter().all(|c| CLI_ONLY.contains(c)) {
            continue;
        }
        if !source.contains(&format!("client().{}(", route.name)) {
            missing.push(format!("{} {} ({})", route.method, route.path, route.name));
        }
    }
    assert!(
        missing.is_empty(),
        "routes without a Tauri command in ui/src-tauri/src/main.rs: {missing:?}"
    );
}

#[test]
fn every_registered_tauri_command_is_defined() {
    let start = UI_COMMANDS
        .find("generate_handler![")
        .expect("invoke handler");
    let list = &UI_COMMANDS[start..];
    let list = &list[list.find('[').unwrap() + 1..list.find(']').unwrap()];
    for name in list.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        assert!(
            UI_COMMANDS.contains(&format!("async fn {name}(")),
            "command {name} is registered but not defined"
        );
    }
}
