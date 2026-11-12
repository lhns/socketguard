//! The apps, peers, groups, tags, grants, reservations and addresses as stored: the state a
//! change is planned against and the ruleset is built from.

use crate::AppState;
use socketguard_core::{Address, App, Grant, Peer, PeerGroup, PortGroup, Reservation, Tag, Target};
use std::collections::HashSet;

/// The apps, peers, groups, tags and grants a change is checked against. A batch edits its
/// own copy as it goes, so later operations see earlier ones (including created refs).
#[derive(Debug, Default, Clone)]
pub struct Catalog {
    pub apps: Vec<App>,
    pub peers: Vec<Peer>,
    pub groups: Vec<PeerGroup>,
    pub tags: Vec<Tag>,
    pub port_groups: Vec<PortGroup>,
    pub grants: Vec<Grant>,
    pub reservations: Vec<Reservation>,
    /// Every address as stored (no computed fields).
    pub addresses: Vec<Address>,
}

impl Catalog {
    /// Tags and, standing in for tags, reservations: what `covered_ports` expands.
    pub fn targets(&self) -> Vec<Tag> {
        socketguard_core::grant_targets(&self.tags, &self.reservations)
    }

    /// The grants that cover the members of a tag: those on the tag itself and those on a
    /// reservation that binds the tag (a new member becomes reachable through both).
    pub fn grants_through_tag(&self, tag_id: &str) -> Vec<Grant> {
        let bound: HashSet<&str> = self
            .reservations
            .iter()
            .filter(|r| {
                r.bindings.iter().any(|b| {
                    matches!(&b.target, socketguard_core::BindingTarget::Tag { tag_id: t } if t == tag_id)
                })
            })
            .map(|r| r.id.as_str())
            .collect();
        self.grants
            .iter()
            .filter(|g| match &g.target {
                Target::Tag(t) => t == tag_id,
                Target::Reservation(r) => bound.contains(r.as_str()),
                Target::App(_) => false,
            })
            .cloned()
            .collect()
    }

    pub fn reservation(&self, id: &str) -> Option<&Reservation> {
        self.reservations.iter().find(|r| r.id == id)
    }

    pub async fn load(state: &AppState) -> anyhow::Result<Self> {
        let db = &state.db;
        Ok(Self {
            apps: db.list_apps().await?,
            peers: db.list_peers().await?,
            groups: db.list_groups().await?,
            tags: db.list_tags().await?,
            port_groups: db.list_port_groups().await?,
            grants: db.list_grants().await?,
            reservations: db.list_reservations().await?,
            addresses: db.list_addresses().await?,
        })
    }

    pub fn app(&self, id: &str) -> Option<&App> {
        self.apps.iter().find(|a| a.id == id)
    }

    pub fn peer(&self, id: &str) -> Option<&Peer> {
        self.peers.iter().find(|p| p.id == id)
    }

    pub fn group(&self, id: &str) -> Option<&PeerGroup> {
        self.groups.iter().find(|g| g.id == id)
    }

    pub fn tag(&self, id: &str) -> Option<&Tag> {
        self.tags.iter().find(|t| t.id == id)
    }

    pub fn port_group(&self, id: &str) -> Option<&PortGroup> {
        self.port_groups.iter().find(|g| g.id == id)
    }
}
