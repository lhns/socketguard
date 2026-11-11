//! Reservations and their bindings (ADR 0047). Changes go through [`super::Write`] so a
//! batch applies them in one transaction; the methods here are the single-call forms and
//! the loaders.

use super::{parse_ts, scope_columns, scope_from_columns, ts, Database, Tx};
use anyhow::{bail, Result};
use socketguard_core::{Address, Binding, BindingTarget, Reservation};
use sqlx::Row;
use std::collections::HashMap;

pub(super) async fn insert_binding_in(tx: &mut Tx<'_>, b: &Binding) -> Result<()> {
    let (app_id, tag_id, (port, proto, group)) = match &b.target {
        BindingTarget::App { app_id, scope } => (Some(app_id), None, scope_columns(scope)),
        BindingTarget::Tag { tag_id } => (None, Some(tag_id), (None, None, None)),
    };
    sqlx::query(
        "INSERT INTO reservation_bindings (id, reservation_id, app_id, port, proto, \
         port_group, tag_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&b.id)
    .bind(&b.reservation_id)
    .bind(app_id)
    .bind(port)
    .bind(proto)
    .bind(group)
    .bind(tag_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(super) async fn insert_reservation_in(tx: &mut Tx<'_>, r: &Reservation) -> Result<()> {
    sqlx::query("INSERT INTO reservations (id, label, created_at) VALUES (?, ?, ?)")
        .bind(&r.id)
        .bind(&r.label)
        .bind(ts(r.created_at))
        .execute(&mut **tx)
        .await?;
    for b in &r.bindings {
        insert_binding_in(tx, b).await?;
    }
    Ok(())
}

/// Delete a reservation with the grants that target it; its bindings and addresses (and
/// their onion keys) go with it by cascade. The caller takes the addresses off their
/// networks first.
pub(super) async fn delete_reservation_in(tx: &mut Tx<'_>, id: &str) -> Result<bool> {
    sqlx::query("DELETE FROM grants WHERE target_kind = 'reservation' AND target_id = ?")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    let r = sqlx::query("DELETE FROM reservations WHERE id = ?")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(r.rows_affected() > 0)
}

pub(super) async fn assign_address_in(
    tx: &mut Tx<'_>,
    address_id: &str,
    reservation_id: &str,
) -> Result<()> {
    // The address stops belonging to its app, so forgetting the app leaves it.
    let r = sqlx::query(
        "UPDATE addresses SET reservation_id = ?, app_id = NULL, port = NULL, proto = NULL, \
         port_group = NULL WHERE id = ?",
    )
    .bind(reservation_id)
    .bind(address_id)
    .execute(&mut **tx)
    .await?;
    if r.rows_affected() == 0 {
        bail!("address {address_id} not found");
    }
    Ok(())
}

impl Database {
    pub async fn list_reservations(&self) -> Result<Vec<Reservation>> {
        self.load_reservations(None).await
    }

    pub async fn get_reservation(&self, id: &str) -> Result<Option<Reservation>> {
        Ok(self.load_reservations(Some(id)).await?.into_iter().next())
    }

    async fn load_reservations(&self, only: Option<&str>) -> Result<Vec<Reservation>> {
        let rows = sqlx::query(
            "SELECT id, label, created_at FROM reservations WHERE (?1 IS NULL OR id = ?1) \
             ORDER BY label",
        )
        .bind(only)
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(Reservation {
                id: r.get("id"),
                label: r.get("label"),
                bindings: Vec::new(),
                created_at: parse_ts(r.get("created_at"))?,
            });
        }
        let bindings = sqlx::query(
            "SELECT id, reservation_id, app_id, port, proto, port_group, tag_id \
             FROM reservation_bindings WHERE (?1 IS NULL OR reservation_id = ?1) ORDER BY rowid",
        )
        .bind(only)
        .fetch_all(&self.pool)
        .await?;
        let mut by_res: HashMap<String, Vec<Binding>> = HashMap::new();
        for r in bindings {
            let target = match (r.get::<Option<String>, _>("app_id"), r.get("tag_id")) {
                (Some(app_id), None) => BindingTarget::App {
                    app_id,
                    scope: scope_from_columns(r.get("port"), r.get("proto"), r.get("port_group"))?,
                },
                (None, Some(tag_id)) => BindingTarget::Tag { tag_id },
                _ => bail!("inconsistent binding row"),
            };
            let reservation_id: String = r.get("reservation_id");
            by_res
                .entry(reservation_id.clone())
                .or_default()
                .push(Binding {
                    id: r.get("id"),
                    reservation_id,
                    target,
                });
        }
        for r in &mut out {
            r.bindings = by_res.remove(&r.id).unwrap_or_default();
        }
        Ok(out)
    }

    /// Insert a reservation with its bindings.
    pub async fn insert_reservation(&self, r: &Reservation) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        insert_reservation_in(&mut tx, r).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Insert the address of a reservation with its locator secret.
    pub async fn insert_reservation_address(
        &self,
        a: &Address,
        secret: Option<&str>,
    ) -> Result<()> {
        self.insert_address_with_secret(a, secret).await
    }

    /// Move an automatic address to a reservation, keeping the locator.
    pub async fn assign_address(&self, address_id: &str, reservation_id: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        assign_address_in(&mut tx, address_id, reservation_id).await?;
        tx.commit().await?;
        Ok(())
    }
}
