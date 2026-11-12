//! The engine's side of Tor and Yggdrasil networks (ADR 0052): which children should run, declared
//! to the supervisor. The engine never starts a process itself; it states what it wants
//! and the supervisor's tasks do it, so a slow or failing start never holds up a pass.

use super::firewall::NODE_KEY_PREFIX;
use super::*;
use crate::children::Desired;
use crate::firewall::ScopeMatch;
use crate::networks::ygg_child;
use crate::networks::ygg_key::{YggKey, KEY_PREFIX};
use crate::ruleset::overlay_addr_scope_id;
use anyhow::Context;
use socketguard_core::config::BackendConfig;
use socketguard_core::setup::YggdrasilBlock;
use socketguard_core::NetworkKind;
use std::sync::atomic::Ordering;

/// Whether a Tor or Yggdrasil network's child may start now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    Open,
    /// Held back; the sentence says until what (shown on the network's card). Tor is never
    /// held; Yggdrasil is, until its block is in force.
    Held(String),
}

pub(super) fn is_yggdrasil(backend: &BackendConfig) -> bool {
    matches!(backend, BackendConfig::Yggdrasil { .. })
}

impl Engine {
    /// The Yggdrasil network the engine manages, if any.
    fn yggdrasil_backend(&self) -> Option<(&String, &ActiveBackend)> {
        self.backends
            .iter()
            .find(|(_, b)| b.network.kind() == NetworkKind::Yggdrasil)
    }

    /// Whether the block of the Yggdrasil network (the node's own address and subnet) is in
    /// the ruleset last applied, and that apply succeeded (ADR 0051). None without a
    /// Yggdrasil network.
    pub async fn yggdrasil_block(&self, state: &AppState) -> Option<YggdrasilBlock> {
        let (id, active) = self.yggdrasil_backend()?;
        let iface = Self::interface_in_use(active);
        // An interface rule holds for an adapter that is not there yet on nftables and pf,
        // not on WFP, which can only bind a filter to an adapter that exists.
        let adapter_ok = self.firewall.blocks_absent_interfaces()
            || iface.as_ref().is_some_and(|name| {
                self.ifaces
                    .list_interfaces()
                    .is_ok_and(|l| l.iter().any(|i| &i.name == name))
            });
        let applied = self.last_applied.lock().unwrap().clone();
        let failed = self.apply_failed.load(Ordering::Relaxed);
        let node_scope = overlay_addr_scope_id(id);
        let (address_blocked, interface_blocked) = match (&applied, failed) {
            (Some(rs), false) => (
                rs.scopes.iter().any(|s| s.id == node_scope),
                adapter_ok
                    && rs.scopes.iter().any(|s| {
                        matches!(&s.matcher, ScopeMatch::Interface { name, .. }
                            if Some(name) == iface.as_ref())
                    }),
            ),
            _ => (false, false),
        };
        let reason = if state.db.disabled().await {
            Some("SocketGuard is turned off".to_string())
        } else if failed {
            Some("the last attempt to apply the firewall rules failed".to_string())
        } else if applied.is_none() {
            Some("the firewall rules are not applied yet".to_string())
        } else if !address_blocked && !adapter_ok {
            Some("the node's address is not known yet, and the firewall can only block an adapter that exists".to_string())
        } else if !address_blocked {
            Some("the node's address is not known yet".to_string())
        } else {
            None
        };
        Some(YggdrasilBlock {
            closed: address_blocked,
            address_blocked,
            interface_blocked,
            reason,
        })
    }

    /// The condition, beyond "SocketGuard is on, the network exists and is not unadopted",
    /// under which the child of `id` runs. Tor needs none. Yggdrasil adds its own:
    /// the ruleset that blocks its address range must be applied and verified first (ADR
    /// 0051), and no other node may run on the host (the node's name and interface would
    /// clash, and the block is written for one node).
    ///
    /// Only a start is gated: a node that runs stays (a later failed apply leaves the
    /// ruleset before it in force, which already closes the node), and the other-node
    /// check is meant for the moment before our own adapter exists.
    async fn child_gate(&self, state: &AppState, id: &str, backend: &BackendConfig) -> Gate {
        if !is_yggdrasil(backend) || self.child_ctx.children.status(id).alive() {
            return Gate::Open;
        }
        // Without a key there is no node to close; the spec says so.
        let Some(key) = self.child_ctx.keys.get(id) else {
            return Gate::Open;
        };
        match self.yggdrasil_block(state).await {
            Some(block) if block.closed => {}
            other => {
                let why = other.and_then(|b| b.reason).unwrap_or_else(|| {
                    "the node's network is not known to the firewall yet".into()
                });
                return Gate::Held(format!(
                    "waiting for the firewall rules that close the node ({why})"
                ));
            }
        }
        let ifaces = self.ifaces.clone();
        let node = key.node();
        let other = tokio::task::spawn_blocking(move || {
            ygg_child::another_node_running(ifaces.as_ref(), &node, ygg_child::adapter_name())
        })
        .await
        .unwrap_or(false);
        if other {
            return Gate::Held(ygg_child::OTHER_NODE.into());
        }
        Gate::Open
    }

    /// The key of the Yggdrasil node `id`, from the database or (a new network,
    /// `fresh`) generated and stored now, and its addresses remembered as the network's
    /// node (ADR 0051), so the first ruleset already closes them. The networks read the key
    /// from `self.child_ctx.keys`.
    pub(super) async fn ensure_child_key(
        &self,
        state: &AppState,
        id: &str,
        fresh: bool,
    ) -> anyhow::Result<()> {
        let setting = format!("{KEY_PREFIX}{id}");
        if fresh {
            // A leftover of a removal that was cut short is not this network's key.
            state.db.delete_setting(&setting).await?;
        }
        let key = match state.db.get_setting(&setting).await? {
            Some(text) => YggKey::from_private_hex(&text)
                .with_context(|| format!("the stored key of network {id}"))?,
            None => {
                let key = YggKey::generate();
                state.db.set_setting(&setting, &key.private_hex()).await?;
                key
            }
        };
        state
            .db
            .set_setting(
                &format!("{NODE_KEY_PREFIX}{id}"),
                &serde_json::to_string(&key.node())?,
            )
            .await?;
        self.child_ctx.keys.insert(id, key);
        Ok(())
    }

    /// [`Engine::ensure_child_key`] for every Yggdrasil network (startup). A key
    /// that cannot be read leaves its network down and says so; it is never replaced.
    pub(super) async fn ensure_child_keys(&self, state: &AppState) {
        for id in self.sorted_backend_ids() {
            if !is_yggdrasil(&self.backends[id].config.backend) {
                continue;
            }
            if let Err(e) = self.ensure_child_key(state, id, false).await {
                error!("Network '{id}': the Yggdrasil key is not usable: {e:#}");
            }
        }
    }

    /// Forget the key of a Yggdrasil network that is being removed, and the
    /// directory with the configuration that holds it (the child has ended).
    pub(super) async fn forget_child_key(&self, state: &AppState, id: &str) {
        self.child_ctx.keys.remove(id);
        self.valves_forget(id);
        if let Err(e) = state.db.delete_setting(&format!("{KEY_PREFIX}{id}")).await {
            warn!("Could not delete the Yggdrasil key of '{id}': {e:#}");
        }
        if let Ok(state_dir) = self.child_ctx.state_dir() {
            let dir = state_dir.join(ygg_child::DIR);
            match std::fs::remove_dir_all(&dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => warn!("Could not remove {}: {e}", dir.display()),
            }
        }
    }

    fn valves_forget(&self, id: &str) {
        self.child_ctx.valves.lock().unwrap().remove(id);
    }

    /// Declare to the supervisor which children should run. Idempotent and quick:
    /// the supervisor only acts on a change. Called at the end of a pass and after every
    /// change that can alter the answer (a network added, removed, enabled, disabled, its
    /// settings changed). Takes no lock of the engine's order; reads the latches only.
    /// Returns whether SocketGuard is off (then every child is being stopped).
    pub(super) async fn sync_children(&self, state: &AppState) -> bool {
        // An unreadable latch counts as "off": failing closed means nothing runs.
        let off = state.db.disabled().await || state.db.unadopted().await.unwrap_or(true);
        for id in self.sorted_backend_ids() {
            let backend = &self.backends[id].config.backend;
            if !backend.runs_child() {
                continue;
            }
            let wish = if off {
                Desired::Stopped
            } else {
                match self.child_gate(state, id, backend).await {
                    Gate::Held(why) => Desired::Waiting(why),
                    Gate::Open => crate::networks::child::child_wish(
                        &self.child_ctx,
                        &self.ifaces,
                        id,
                        backend,
                    ),
                }
            };
            self.child_ctx.children.set_desired(id, wish);
        }
        off
    }

    /// [`Engine::sync_children`], then, when SocketGuard is off, wait until the children
    /// are gone (`disable`: afterwards nothing of ours is running).
    pub(super) async fn sync_children_and_wait(&self, state: &AppState) {
        if self.sync_children(state).await {
            for id in self.sorted_backend_ids() {
                if self.backends[id].config.backend.runs_child() {
                    self.child_ctx.children.wait_stopped(id).await;
                }
            }
        }
    }

    /// Stop the child of a network that is about to go and wait for it to end.
    pub(super) async fn stop_child(&self, id: &str) {
        if self
            .backends
            .get(id)
            .is_some_and(|b| b.config.backend.runs_child())
        {
            self.child_ctx.children.remove(id).await;
        }
    }
}
