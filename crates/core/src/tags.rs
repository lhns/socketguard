//! Tags (ADR 0043, 0047): named sets of apps (or scopes of apps) that grants can target,
//! and the expansion of a grant on a tag into what it covers per app.

use crate::config::glob_match;
use crate::model::{App, AppId, Grant, GrantId, NetworkId, Subject, TagId, Target};
use crate::scope::{
    raw_scope_ports, scope_ports, PortRange, PortRangeSet, Scope, ScopePorts, SocketGroup,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One member of a tag: an app with a scope (all of it, one port, or one socket group).
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TagMember {
    pub app_id: AppId,
    #[serde(default)]
    pub scope: Scope,
}

#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tag {
    pub id: TagId,
    pub label: String,
    /// Globs on the process name or the executable path; discovery adds matching new apps.
    #[serde(default)]
    pub patterns: Vec<String>,
    pub members: Vec<TagMember>,
    /// Apps removed from the tag by hand although a pattern matches them; discovery and
    /// pattern changes do not add them back.
    #[serde(default)]
    pub excluded: Vec<AppId>,
    pub created_at: DateTime<Utc>,
}

impl Tag {
    /// Whether one of the tag's patterns matches the app's process name or executable path.
    pub fn matches(&self, app: &App) -> bool {
        patterns_match(&self.patterns, &app.process_name, app.exe_path.as_deref())
    }

    /// The apps among `apps` that the patterns would add: matching, not excluded by hand
    /// and not yet members as a whole.
    pub fn pattern_candidates<'a>(&self, apps: &'a [App]) -> Vec<&'a App> {
        apps.iter()
            .filter(|a| {
                self.matches(a)
                    && !self.excluded.contains(&a.id)
                    && !self
                        .members
                        .iter()
                        .any(|m| m.app_id == a.id && m.scope.is_all())
            })
            .collect()
    }
}

/// Whether any of `patterns` matches `process_name` or `exe_path` (the process filter's
/// glob: case-insensitive, `*` and `?`).
pub fn patterns_match(patterns: &[String], process_name: &str, exe_path: Option<&str>) -> bool {
    patterns
        .iter()
        .any(|p| glob_match(p, process_name) || exe_path.is_some_and(|e| glob_match(p, e)))
}

/// Why an effective access exists, for display.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AccessOrigin {
    /// A grant on the app itself, to a peer or Anyone.
    Direct,
    /// A grant on a tag the app is in.
    Tag { tag_id: TagId },
    /// A grant on the app to a peer group.
    Group { group_id: String },
}

/// One access an app has: a grant with the reason it applies and the ports it covers on
/// this app (for a tag grant, the grant's scope narrowed by the members' scopes).
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveAccess {
    pub grant_id: GrantId,
    /// The grant's own scope.
    pub scope: Scope,
    /// What the grant covers on this app now: detected ports, explicit ports and the
    /// ranges of socket groups, merged.
    pub ports: Vec<PortRange>,
    pub network_id: Option<NetworkId>,
    pub subject: Subject,
    pub origin: AccessOrigin,
}

/// The ports of `app` that `grant` covers, or None when it does not apply to the app:
///
/// - a grant on the app covers the ports of its scope on the app,
/// - a grant on a tag covers, for each member of the app, the member's ports narrowed to
///   the grant's own scope (which needs no attachment), merged over the members. None if
///   the app is no member, or if neither side is `All` and the two leave nothing.
///
/// `foreign` are the ports other apps listen on, see [`scope_ports`].
pub fn covered_ports(
    grant: &Grant,
    tags: &[Tag],
    app: &App,
    groups: &[SocketGroup],
    foreign: &PortRangeSet,
) -> Option<ScopePorts> {
    match &grant.target {
        Target::App(a) if *a == app.id => Some(scope_ports(app, &grant.scope, groups, foreign)),
        Target::App(_) => None,
        Target::Tag(tag_id) => {
            let tag = tags.iter().find(|t| &t.id == tag_id)?;
            let raw = raw_scope_ports(&grant.scope, groups);
            let members: Vec<&TagMember> =
                tag.members.iter().filter(|m| m.app_id == app.id).collect();
            if members.is_empty() {
                return None;
            }
            let covered = members.iter().fold(ScopePorts::empty(), |acc, m| {
                acc.union(&scope_ports(app, &m.scope, groups, foreign).intersect(&raw))
            });
            let open = grant.scope.is_all() || members.iter().any(|m| m.scope.is_all());
            (!covered.is_empty() || open).then_some(covered)
        }
    }
}

/// A grant that applies to one app: the grant itself, re-targeted at the app (same id,
/// subject and network), and the ports it covers there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppGrant {
    pub grant: Grant,
    pub ports: ScopePorts,
}

/// The grants that apply to `app`, with tag grants expanded and the covered ports worked
/// out as in [`covered_ports`]. Grants that cover nothing are left out. The ruleset and the
/// networks work on these.
pub fn grants_for_app(
    grants: &[Grant],
    tags: &[Tag],
    app: &App,
    groups: &[SocketGroup],
    foreign: &PortRangeSet,
) -> Vec<AppGrant> {
    grants
        .iter()
        .filter_map(|g| {
            let ports = covered_ports(g, tags, app, groups, foreign)?;
            (!ports.is_empty()).then(|| AppGrant {
                grant: Grant {
                    target: Target::App(app.id.clone()),
                    ..g.clone()
                },
                ports,
            })
        })
        .collect()
}

/// The accesses of `app` with their origin, for display.
pub fn effective_access(
    grants: &[Grant],
    tags: &[Tag],
    app: &App,
    groups: &[SocketGroup],
) -> Vec<EffectiveAccess> {
    let none = PortRangeSet::new();
    grants
        .iter()
        .filter_map(|g| {
            let origin = match (&g.target, &g.subject) {
                (Target::Tag(t), _) => AccessOrigin::Tag { tag_id: t.clone() },
                (Target::App(_), Subject::Group(gid)) => AccessOrigin::Group {
                    group_id: gid.clone(),
                },
                (Target::App(_), _) => AccessOrigin::Direct,
            };
            let ports = covered_ports(g, tags, app, groups, &none)?;
            Some(EffectiveAccess {
                grant_id: g.id.clone(),
                scope: g.scope.clone(),
                ports: ports.ranges(),
                network_id: g.network_id.clone(),
                subject: g.subject.clone(),
                origin,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PortRef;
    use crate::scope::tests::{app_with, group};
    use crate::types::Protocol;

    fn p(port: u16) -> PortRef {
        PortRef {
            port,
            proto: Protocol::Tcp,
        }
    }

    fn tag(members: Vec<TagMember>) -> Tag {
        Tag {
            id: "t".into(),
            label: "dev".into(),
            patterns: vec![],
            members,
            excluded: vec![],
            created_at: Utc::now(),
        }
    }

    fn member(app: &str, scope: Scope) -> TagMember {
        TagMember {
            app_id: app.into(),
            scope,
        }
    }

    fn grant(target: Target, scope: Scope, subject: Subject) -> Grant {
        Grant {
            id: "g".into(),
            target,
            scope,
            network_id: None,
            subject,
            created_at: Utc::now(),
        }
    }

    fn texts(c: Option<ScopePorts>) -> Vec<String> {
        c.map(|c| c.ranges().iter().map(|r| r.to_string()).collect())
            .unwrap_or_default()
    }

    fn none() -> PortRangeSet {
        PortRangeSet::new()
    }

    #[test]
    fn a_tag_grant_covers_each_member_narrowed_by_both_scopes() {
        let a = app_with("a", &[(22, true), (80, true), (443, true)]);
        let b = app_with("b", &[(80, true)]);
        let nobody = app_with("nobody", &[(80, true)]);
        let tags = [tag(vec![
            member("a", Scope::All),
            member("b", Scope::port(p(80))),
            member("c", Scope::port(p(80))),
        ])];
        let g = grant(Target::Tag("t".into()), Scope::All, Subject::Anyone);
        assert_eq!(
            texts(covered_ports(&g, &tags, &a, &[], &none())),
            ["22/tcp", "80/tcp", "443/tcp"]
        );
        assert_eq!(texts(covered_ports(&g, &tags, &b, &[], &none())), ["80/tcp"]);
        assert!(covered_ports(&g, &tags, &nobody, &[], &none()).is_none());

        let g = grant(Target::Tag("t".into()), Scope::port(p(443)), Subject::Anyone);
        assert_eq!(texts(covered_ports(&g, &tags, &a, &[], &none())), ["443/tcp"]);
        assert!(
            covered_ports(&g, &tags, &b, &[], &none()).is_none(),
            "both set and different: nothing"
        );
        let g = grant(Target::Tag("t".into()), Scope::port(p(80)), Subject::Anyone);
        assert_eq!(texts(covered_ports(&g, &tags, &b, &[], &none())), ["80/tcp"]);
    }

    #[test]
    fn several_members_of_one_app_merge() {
        let a = app_with("a", &[(80, true), (22, true), (25, true)]);
        let tags = [tag(vec![
            member("a", Scope::port(p(80))),
            member("a", Scope::port(p(22))),
            member("a", Scope::port(p(80))),
        ])];
        let g = grant(Target::Tag("t".into()), Scope::All, Subject::Anyone);
        assert_eq!(
            texts(covered_ports(&g, &tags, &a, &[], &none())),
            ["22/tcp", "80/tcp"]
        );
        let tags = [tag(vec![
            member("a", Scope::port(p(80))),
            member("a", Scope::All),
        ])];
        assert_eq!(
            texts(covered_ports(&g, &tags, &a, &[], &none())),
            ["22/tcp", "25/tcp", "80/tcp"]
        );
    }

    #[test]
    fn groups_narrow_and_widen_tag_grants() {
        let a = app_with("a", &[(21, true)]);
        let groups = [
            group("passive", &["50000-50100/tcp"], &["a"]),
            group("wide", &["50050-60000/tcp"], &[]),
        ];
        // A member by group, a grant for everything: the group's ranges.
        let tags = [tag(vec![member("a", Scope::group("passive"))])];
        let g = grant(Target::Tag("t".into()), Scope::All, Subject::Anyone);
        assert_eq!(
            texts(covered_ports(&g, &tags, &a, &groups, &none())),
            ["50000-50100/tcp"]
        );
        // Member group intersected with the grant's group (which needs no attachment).
        let g = grant(
            Target::Tag("t".into()),
            Scope::group("wide"),
            Subject::Anyone,
        );
        assert_eq!(
            texts(covered_ports(&g, &tags, &a, &groups, &none())),
            ["50050-50100/tcp"]
        );
        // A whole-app member and a grant for a group the app does not have: only what the
        // app has inside it (here the attached group's overlap).
        let tags = [tag(vec![member("a", Scope::All)])];
        assert_eq!(
            texts(covered_ports(&g, &tags, &a, &groups, &none())),
            ["50050-50100/tcp"]
        );
        let other = [group("far", &["60000-61000/tcp"], &[])];
        let g_far = grant(Target::Tag("t".into()), Scope::group("far"), Subject::Anyone);
        assert!(covered_ports(&g_far, &tags, &a, &other, &none())
            .unwrap()
            .is_empty());
        // A grant for an attached group on a whole-app member: the whole group.
        let g = grant(
            Target::Tag("t".into()),
            Scope::group("passive"),
            Subject::Anyone,
        );
        assert_eq!(
            texts(covered_ports(&g, &tags, &a, &groups, &none())),
            ["50000-50100/tcp"]
        );
        // A whole-app member with a port grant inside the attached group's range.
        let g = grant(
            Target::Tag("t".into()),
            Scope::port(p(50010)),
            Subject::Anyone,
        );
        assert_eq!(
            texts(covered_ports(&g, &tags, &a, &groups, &none())),
            ["50010/tcp"]
        );
        // A direct grant on an app by an unattached group covers nothing.
        let g = grant(
            Target::App("a".into()),
            Scope::group("wide"),
            Subject::Anyone,
        );
        assert!(covered_ports(&g, &tags, &a, &groups, &none())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn app_grants_and_origins() {
        let a = app_with("a", &[(1, true), (2, true)]);
        let tags = [tag(vec![member("a", Scope::All)])];
        let grants = [
            grant(
                Target::App("a".into()),
                Scope::port(p(1)),
                Subject::Peer("x".into()),
            ),
            grant(
                Target::App("a".into()),
                Scope::All,
                Subject::Group("grp".into()),
            ),
            grant(Target::App("b".into()), Scope::All, Subject::Anyone),
            grant(Target::Tag("t".into()), Scope::All, Subject::Anyone),
            grant(Target::Tag("gone".into()), Scope::All, Subject::Anyone),
        ];
        let narrowed = grants_for_app(&grants, &tags, &a, &[], &none());
        assert_eq!(narrowed.len(), 3);
        assert!(narrowed
            .iter()
            .all(|g| g.grant.target == Target::App("a".to_string())));
        let access = effective_access(&grants, &tags, &a, &[]);
        let origins: Vec<_> = access.iter().map(|e| e.origin.clone()).collect();
        assert_eq!(
            origins,
            [
                AccessOrigin::Direct,
                AccessOrigin::Group {
                    group_id: "grp".into()
                },
                AccessOrigin::Tag { tag_id: "t".into() }
            ]
        );
        assert_eq!(access[0].scope, Scope::port(p(1)));
        assert_eq!(access[0].ports.len(), 1);
        assert_eq!(access[2].ports[0].to_string(), "1-2/tcp");
    }

    #[test]
    fn grants_that_cover_nothing_are_not_enforced() {
        let a = app_with("a", &[]);
        let grants = [grant(Target::App("a".into()), Scope::All, Subject::Anyone)];
        assert!(grants_for_app(&grants, &[], &a, &[], &none()).is_empty());
        // ... but are still listed as an access.
        assert_eq!(effective_access(&grants, &[], &a, &[]).len(), 1);
    }

    #[test]
    fn patterns_match_the_process_name_or_the_path() {
        let pats = vec!["py*".to_string(), "/opt/dev/*".to_string()];
        assert!(patterns_match(&pats, "python3", None));
        assert!(patterns_match(&pats, "server", Some("/opt/dev/bin/server")));
        assert!(!patterns_match(&pats, "nginx", Some("/usr/sbin/nginx")));
        assert!(!patterns_match(&[], "python3", None));
    }
}
