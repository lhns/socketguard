//! Example of snapshot testing with `insta` on a pure function.
//! Review changes with `cargo insta review` (or accept with INSTA_UPDATE=always).

use socketguard_core::config::glob_match;

#[test]
fn glob_match_table() {
    let cases = [
        ("*", "anything"),
        ("ssh*", "sshd"),
        ("ssh*", "xsshd"),
        ("*.exe", "node.exe"),
        ("*.exe", "node"),
        ("n?de", "node"),
        ("n?de", "nde"),
    ];
    let out: String = cases
        .iter()
        .map(|(p, t)| format!("{p:<8} {t:<10} {}\n", glob_match(p, t)))
        .collect();
    insta::assert_snapshot!(out);
}
