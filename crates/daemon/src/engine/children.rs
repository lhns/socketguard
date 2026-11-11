//! The engine's side of managed networks (ADR 0052): which children should run, declared
//! to the supervisor. The engine never starts a process itself; it states what it wants
//! and the supervisor's tasks do it, so a slow or failing start never holds up a pass.

use super::*;
use crate::children::Desired;
use socketguard_core::config::BackendConfig;

/// Whether a managed network's child may start now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    Open,
    /// Held back; the sentence says until what (shown on the network's card). Tor is never
    /// held; managed Yggdrasil is, until its block is in force.
    #[allow(dead_code)]
    Held(String),
}

impl Engine {
    /// The condition, beyond "SocketGuard is on, the network exists and is not unadopted",
    /// under which the child of `id` runs. Tor needs none. Managed Yggdrasil adds its own
    /// here: the ruleset that blocks its address range must be applied and verified first
    /// (ADR 0051), and no other node may run on the host.
    fn child_gate(&self, _id: &str, _backend: &BackendConfig) -> Gate {
        Gate::Open
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
                match self.child_gate(id, backend) {
                    Gate::Held(why) => Desired::Waiting(why),
                    Gate::Open => crate::networks::managed::child_wish(&self.managed, id, backend),
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
