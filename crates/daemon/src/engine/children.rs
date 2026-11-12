//! The engine's side of managed networks (ADR 0052): which children should run, declared
//! to the supervisor. The engine never starts a process itself; it states what it wants
//! and the supervisor's tasks do it, so a slow or failing start never holds up a pass.

use super::firewall::NODE_KEY_PREFIX;
use super::*;
use crate::children::Desired;
use crate::networks::ygg_key::{YggKey, KEY_PREFIX};
use crate::networks::ygg_managed;
use anyhow::Context;
use socketguard_core::config::BackendConfig;

/// Whether a managed network's child may start now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    Open,
    /// Held back; the sentence says until what (shown on the network's card). Tor is never
    /// held; managed Yggdrasil is, until its block is in force.
    Held(String),
}

pub(super) fn is_managed_yggdrasil(backend: &BackendConfig) -> bool {
    matches!(backend, BackendConfig::Yggdrasil { managed: true, .. })
}

impl Engine {
    /// The condition, beyond "SocketGuard is on, the network exists and is not unadopted",
    /// under which the child of `id` runs. Tor needs none. Managed Yggdrasil adds its own:
    /// the ruleset that blocks its address range must be applied and verified first (ADR
    /// 0051), and no other node may run on the host (the node's name and interface would
    /// clash, and the block is written for one node).
    ///
    /// Only a start is gated: a node that runs stays (a later failed apply leaves the
    /// ruleset before it in force, which already closes the node), and the other-node
    /// check is meant for the moment before our own adapter exists.
    async fn child_gate(&self, state: &AppState, id: &str, backend: &BackendConfig) -> Gate {
        if !is_managed_yggdrasil(backend) || self.managed.children.status(id).alive() {
            return Gate::Open;
        }
        // Without a key there is no node to close; the spec says so.
        let Some(key) = self.managed.keys.get(id) else {
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
            ygg_managed::another_node_running(ifaces.as_ref(), &node, ygg_managed::adapter_name())
        })
        .await
        .unwrap_or(false);
        if other {
            return Gate::Held(ygg_managed::OTHER_NODE.into());
        }
        Gate::Open
    }

    /// The key of the managed Yggdrasil node `id`, from the database or (a new network,
    /// `fresh`) generated and stored now, and its addresses remembered as the network's
    /// node (ADR 0051), so the first ruleset already closes them. The networks read the key
    /// from `self.managed.keys`.
    pub(super) async fn ensure_managed_key(
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
        self.managed.keys.insert(id, key);
        Ok(())
    }

    /// [`Engine::ensure_managed_key`] for every managed Yggdrasil network (startup). A key
    /// that cannot be read leaves its network down and says so; it is never replaced.
    pub(super) async fn ensure_managed_keys(&self, state: &AppState) {
        for id in self.sorted_backend_ids() {
            if !is_managed_yggdrasil(&self.backends[id].config.backend) {
                continue;
            }
            if let Err(e) = self.ensure_managed_key(state, id, false).await {
                error!("Network '{id}': the Yggdrasil key is not usable: {e:#}");
            }
        }
    }

    /// Forget the key of a managed Yggdrasil network that is being removed, and the
    /// directory with the configuration that holds it (the child has ended).
    pub(super) async fn forget_managed_key(&self, state: &AppState, id: &str) {
        self.managed.keys.remove(id);
        self.valves_forget(id);
        if let Err(e) = state.db.delete_setting(&format!("{KEY_PREFIX}{id}")).await {
            warn!("Could not delete the Yggdrasil key of '{id}': {e:#}");
        }
        if let Ok(state_dir) = self.managed.state_dir() {
            let dir = state_dir.join(ygg_managed::DIR);
            match std::fs::remove_dir_all(&dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => warn!("Could not remove {}: {e}", dir.display()),
            }
        }
    }

    fn valves_forget(&self, id: &str) {
        self.managed.valves.lock().unwrap().remove(id);
    }

    /// Declare to the supervisor which managed children should run. Idempotent and quick:
    /// the supervisor only acts on a change. Called at the end of a pass and after every
    /// change that can alter the answer (a network added, removed, enabled, disabled, its
    /// settings changed). Takes no lock of the engine's order; reads the latches only.
    /// Returns whether SocketGuard is off (then every child is being stopped).
    pub(super) async fn sync_children(&self, state: &AppState) -> bool {
        // An unreadable latch counts as "off": failing closed means nothing runs.
        let off = state.db.disabled().await || state.db.unadopted().await.unwrap_or(true);
        for id in self.sorted_backend_ids() {
            let backend = &self.backends[id].config.backend;
            if !backend.is_managed() {
                continue;
            }
            let wish = if off {
                Desired::Stopped
            } else {
                match self.child_gate(state, id, backend).await {
                    Gate::Held(why) => Desired::Waiting(why),
                    Gate::Open => crate::networks::managed::child_wish(
                        &self.managed,
                        &self.ifaces,
                        id,
                        backend,
                    ),
                }
            };
            self.managed.children.set_desired(id, wish);
        }
        off
    }

    /// [`Engine::sync_children`], then, when SocketGuard is off, wait until the children
    /// are gone (`disable`: afterwards nothing of ours is running).
    pub(super) async fn sync_children_and_wait(&self, state: &AppState) {
        if self.sync_children(state).await {
            for id in self.sorted_backend_ids() {
                if self.backends[id].config.backend.is_managed() {
                    self.managed.children.wait_stopped(id).await;
                }
            }
        }
    }

    /// Stop the child of a network that is about to go and wait for it to end.
    pub(super) async fn stop_child(&self, id: &str) {
        if self
            .backends
            .get(id)
            .is_some_and(|b| b.config.backend.is_managed())
        {
            self.managed.children.remove(id).await;
        }
    }
}
