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
