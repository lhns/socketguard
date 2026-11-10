//! Tags (ADR 0043): named sets of apps (or single ports of apps) that grants can target,
//! and the expansion of a grant on a tag into what it covers per app.

use crate::config::glob_match;
use crate::model::{App, AppId, Grant, GrantId, NetworkId, PortRef, Subject, TagId, Target};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One member of a tag: a whole app, or one port of it.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TagMember {
    pub app_id: AppId,
    /// None = every port of the app.
    #[serde(default)]
    pub port: Option<PortRef>,
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
                        .any(|m| m.app_id == a.id && m.port.is_none())
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

/// One access an app has: a grant narrowed to this app (by a tag member's port) with the
/// reason it applies.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveAccess {
    pub grant_id: GrantId,
    /// None = every port of the app.
    pub port: Option<PortRef>,
    pub network_id: Option<NetworkId>,
    pub subject: Subject,
    pub origin: AccessOrigin,
}

/// The ports of `app_id` that `grant` covers, as the grant's port narrowed by each member:
/// `[None]` = every port; empty = not covered. Both a member port and the grant port set
/// and different covers nothing through that member.
pub fn covered_ports(grant: &Grant, tags: &[Tag], app_id: &str) -> Vec<Option<PortRef>> {
    match &grant.target {
        Target::App(a) if a == app_id => vec![grant.port],
        Target::App(_) => vec![],
        Target::Tag(tag_id) => {
            let Some(tag) = tags.iter().find(|t| &t.id == tag_id) else {
                return vec![];
            };
            let mut ports: Vec<PortRef> = Vec::new();
            for m in tag.members.iter().filter(|m| m.app_id == app_id) {
                match (m.port, grant.port) {
                    (None, None) => return vec![None],
                    (Some(p), None) | (None, Some(p)) => ports.push(p),
                    (Some(a), Some(b)) if a == b => ports.push(a),
                    (Some(_), Some(_)) => {}
                }
            }
            ports.sort();
            ports.dedup();
            ports.into_iter().map(Some).collect()
        }
    }
}

/// The grants that apply to `app_id`, with tag grants expanded: each result is a grant on
/// the app itself (same id, subject and network) whose port is narrowed as in
/// [`covered_ports`]. The ruleset and the networks work on these.
pub fn grants_for_app(grants: &[Grant], tags: &[Tag], app_id: &str) -> Vec<Grant> {
    grants
        .iter()
        .flat_map(|g| {
            covered_ports(g, tags, app_id)
                .into_iter()
                .map(|port| Grant {
                    target: Target::App(app_id.to_string()),
                    port,
                    ..g.clone()
                })
        })
        .collect()
}

/// [`grants_for_app`] with the origin of each access.
pub fn effective_access(grants: &[Grant], tags: &[Tag], app_id: &str) -> Vec<EffectiveAccess> {
    grants
        .iter()
        .flat_map(|g| {
            let origin = match (&g.target, &g.subject) {
                (Target::Tag(t), _) => AccessOrigin::Tag { tag_id: t.clone() },
                (Target::App(_), Subject::Group(gid)) => AccessOrigin::Group {
                    group_id: gid.clone(),
                },
                (Target::App(_), _) => AccessOrigin::Direct,
            };
            covered_ports(g, tags, app_id)
                .into_iter()
                .map(move |port| EffectiveAccess {
                    grant_id: g.id.clone(),
                    port,
                    network_id: g.network_id.clone(),
                    subject: g.subject.clone(),
                    origin: origin.clone(),
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn member(app: &str, port: Option<PortRef>) -> TagMember {
        TagMember {
            app_id: app.into(),
            port,
        }
    }

    fn grant(target: Target, port: Option<PortRef>, subject: Subject) -> Grant {
        Grant {
            id: "g".into(),
            target,
            port,
            network_id: None,
            subject,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn a_tag_grant_covers_each_member_narrowed_by_both_ports() {
        let tags = [tag(vec![
            member("a", None),
            member("b", Some(p(80))),
            member("c", Some(p(80))),
        ])];
        let g = grant(Target::Tag("t".into()), None, Subject::Anyone);
        assert_eq!(covered_ports(&g, &tags, "a"), [None]);
        assert_eq!(covered_ports(&g, &tags, "b"), [Some(p(80))]);
        assert!(covered_ports(&g, &tags, "nobody").is_empty());

        let g = grant(Target::Tag("t".into()), Some(p(443)), Subject::Anyone);
        assert_eq!(covered_ports(&g, &tags, "a"), [Some(p(443))]);
        assert!(
            covered_ports(&g, &tags, "b").is_empty(),
            "both set and different: nothing"
        );
        let g = grant(Target::Tag("t".into()), Some(p(80)), Subject::Anyone);
        assert_eq!(covered_ports(&g, &tags, "b"), [Some(p(80))]);
    }

    #[test]
    fn several_members_of_one_app_merge() {
        let tags = [tag(vec![
            member("a", Some(p(80))),
            member("a", Some(p(22))),
            member("a", Some(p(80))),
        ])];
        let g = grant(Target::Tag("t".into()), None, Subject::Anyone);
        assert_eq!(covered_ports(&g, &tags, "a"), [Some(p(22)), Some(p(80))]);
        let tags = [tag(vec![member("a", Some(p(80))), member("a", None)])];
        assert_eq!(covered_ports(&g, &tags, "a"), [None]);
    }

    #[test]
    fn app_grants_and_origins() {
        let tags = [tag(vec![member("a", None)])];
        let grants = [
            grant(
                Target::App("a".into()),
                Some(p(1)),
                Subject::Peer("x".into()),
            ),
            grant(Target::App("a".into()), None, Subject::Group("grp".into())),
            grant(Target::App("b".into()), None, Subject::Anyone),
            grant(Target::Tag("t".into()), None, Subject::Anyone),
            grant(Target::Tag("gone".into()), None, Subject::Anyone),
        ];
        let narrowed = grants_for_app(&grants, &tags, "a");
        assert_eq!(narrowed.len(), 3);
        assert!(narrowed
            .iter()
            .all(|g| g.target == Target::App("a".to_string())));
        let origins: Vec<_> = effective_access(&grants, &tags, "a")
            .into_iter()
            .map(|e| e.origin)
            .collect();
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
