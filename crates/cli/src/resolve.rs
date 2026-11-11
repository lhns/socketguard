//! Finding apps, peers and groups by what the user typed: an id, a unique id prefix, or a
//! name. Ambiguity is an error that lists the candidates.

use socketguard_core::{App, Peer, PeerGroup};

pub trait Named {
    fn id(&self) -> &str;
    /// The name the user can type (app name, peer or group label).
    fn name(&self) -> &str;
    /// One line for the candidate list.
    fn describe(&self) -> String {
        format!("{}  {}", short(self.id()), self.name())
    }
}

impl Named for App {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn describe(&self) -> String {
        match &self.exe_path {
            Some(p) => format!("{}  {}  ({p})", short(&self.id), self.name),
            None => format!("{}  {}", short(&self.id), self.name),
        }
    }
}

impl Named for Peer {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> &str {
        &self.label
    }
}

impl Named for socketguard_core::Tag {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> &str {
        &self.label
    }
}

impl Named for socketguard_core::ReservationView {
    fn id(&self) -> &str {
        &self.reservation.id
    }
    fn name(&self) -> &str {
        &self.reservation.label
    }
}

impl Named for socketguard_core::PortGroup {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> &str {
        &self.label
    }
}

impl Named for PeerGroup {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> &str {
        &self.label
    }
}

/// Plain ids (addresses, credentials, grants) have no name: only the id forms match.
impl Named for String {
    fn id(&self) -> &str {
        self
    }
    fn name(&self) -> &str {
        ""
    }
    fn describe(&self) -> String {
        self.clone()
    }
}

/// The first 8 characters of an id, as shown in tables.
pub fn short(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResolveError {
    NotFound {
        kind: &'static str,
        query: String,
    },
    Ambiguous {
        kind: &'static str,
        query: String,
        candidates: Vec<String>,
    },
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::NotFound { kind, query } => write!(f, "no {kind} matches {query:?}"),
            ResolveError::Ambiguous {
                kind,
                query,
                candidates,
            } => {
                write!(f, "{query:?} matches more than one {kind}; use an id:")?;
                for c in candidates {
                    write!(f, "\n  {c}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ResolveError {}

/// Order: exact id; exact name (case-insensitive); unique id prefix. An empty query
/// matches nothing.
pub fn resolve<'a, T: Named>(
    kind: &'static str,
    items: &'a [T],
    query: &str,
) -> Result<&'a T, ResolveError> {
    if query.is_empty() {
        return Err(ResolveError::NotFound {
            kind,
            query: String::new(),
        });
    }
    if let Some(item) = items.iter().find(|i| i.id() == query) {
        return Ok(item);
    }
    let pick = |matches: Vec<&'a T>| -> Result<Option<&'a T>, ResolveError> {
        match matches.as_slice() {
            [] => Ok(None),
            [one] => Ok(Some(*one)),
            many => Err(ResolveError::Ambiguous {
                kind,
                query: query.to_string(),
                candidates: many.iter().map(|i| i.describe()).collect(),
            }),
        }
    };
    let by_name = items
        .iter()
        .filter(|i| i.name().eq_ignore_ascii_case(query))
        .collect();
    if let Some(item) = pick(by_name)? {
        return Ok(item);
    }
    let q = query.to_ascii_lowercase();
    let by_prefix = items
        .iter()
        .filter(|i| i.id().to_ascii_lowercase().starts_with(&q))
        .collect();
    pick(by_prefix)?.ok_or(ResolveError::NotFound {
        kind,
        query: query.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: &str, label: &str) -> Peer {
        Peer {
            id: id.into(),
            label: label.into(),
            credentials: vec![],
            groups: vec![],
            created_at: chrono::DateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn id_name_and_prefix() {
        let peers = vec![peer("abc123", "alice"), peer("abd456", "Bob")];
        assert_eq!(resolve("peer", &peers, "abc123").unwrap().label, "alice");
        assert_eq!(resolve("peer", &peers, "bob").unwrap().label, "Bob");
        assert_eq!(resolve("peer", &peers, "abd").unwrap().label, "Bob");
        assert!(matches!(
            resolve("peer", &peers, "ab"),
            Err(ResolveError::Ambiguous { .. })
        ));
        assert!(matches!(
            resolve("peer", &peers, "zzz"),
            Err(ResolveError::NotFound { .. })
        ));
    }

    #[test]
    fn a_name_beats_a_prefix_and_duplicate_names_are_ambiguous() {
        let peers = vec![peer("bob0001", "x"), peer("zzz", "bob")];
        assert_eq!(resolve("peer", &peers, "bob").unwrap().id, "zzz");
        let dup = vec![peer("1", "same"), peer("2", "same")];
        let err = resolve("peer", &dup, "same").unwrap_err().to_string();
        assert!(
            err.contains("more than one peer") && err.contains("\n  1  same"),
            "{err}"
        );
    }

    #[test]
    fn plain_ids() {
        let ids = vec!["aaa1".to_string(), "aab2".to_string()];
        assert_eq!(resolve("grant", &ids, "aab").unwrap(), "aab2");
        assert_eq!(resolve("grant", &ids, "AAB2").unwrap(), "aab2");
        assert!(matches!(
            resolve("grant", &ids, "aa"),
            Err(ResolveError::Ambiguous { .. })
        ));
        assert!(resolve("grant", &ids, "").is_err());
        // An empty query matches nothing, not even the only item.
        assert!(resolve("grant", &ids[..1], "").is_err());
    }
}
