//! Every API route is reachable from a CLI command (ADR 0033), and the table names only
//! commands that exist. The client crate's own table is compared with the daemon's
//! routes in the daemon's tests.

use clap::CommandFactory;
use socketguard_cli::{cli::Cli, CLI_ROUTES};
use socketguard_daemon::api::ROUTES;
use std::collections::BTreeSet;

#[test]
fn every_route_is_reachable_from_a_cli_command() {
    let api: BTreeSet<(String, String)> = ROUTES
        .iter()
        .map(|(m, p)| (m.to_string(), p.to_string()))
        .collect();
    let cli: BTreeSet<(String, String)> = CLI_ROUTES
        .iter()
        .map(|r| (r.http_method.to_string(), r.path.to_string()))
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
fn the_client_has_a_method_for_every_route_of_the_table() {
    let client: BTreeSet<(String, String)> = socketguard_client::CLIENT_ROUTES
        .iter()
        .map(|(m, p)| (m.to_string(), p.to_string()))
        .collect();
    for r in CLI_ROUTES {
        assert!(
            client.contains(&(r.http_method.to_string(), r.path.to_string())),
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
