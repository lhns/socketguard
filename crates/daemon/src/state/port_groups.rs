//! Port groups (ADR 0047): named port sets that are attached to apps and then usable as
//! a scope. Changes go through [`super::Write`] so a batch applies them in one transaction.

use super::{parse_ts, ts, Database, Tx};
use anyhow::Result;
use socketguard_core::{PortGroup, PortRange};
use sqlx::Row;
use std::collections::HashMap;

pub(super) async fn insert_port_group_in(tx: &mut Tx<'_>, g: &PortGroup) -> Result<()> {
    sqlx::query("INSERT INTO port_groups (id, label, ports, created_at) VALUES (?, ?, ?, ?)")
        .bind(&g.id)
        .bind(&g.label)
        .bind(serde_json::to_string(&g.ports)?)
        .bind(ts(g.created_at))
        .execute(&mut **tx)
        .await?;
    for app_id in &g.apps {
        attach_in(tx, &g.id, app_id).await?;
    }
    Ok(())
}

pub(super) async fn update_port_group_in(
    tx: &mut Tx<'_>,
    id: &str,
    label: Option<&str>,
    ports: Option<&[PortRange]>,
) -> Result<()> {
    let ports = ports.map(serde_json::to_string).transpose()?;
    sqlx::query(
        "UPDATE port_groups SET label = COALESCE(?, label), ports = COALESCE(?, ports) \
         WHERE id = ?",
    )
    .bind(label)
    .bind(ports)
    .bind(id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(super) async fn delete_port_group_in(tx: &mut Tx<'_>, id: &str) -> Result<()> {
    // The attachments go with it (ON DELETE CASCADE).
    sqlx::query("DELETE FROM port_groups WHERE id = ?")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub(super) async fn attach_in(tx: &mut Tx<'_>, group_id: &str, app_id: &str) -> Result<()> {
    sqlx::query("INSERT OR IGNORE INTO port_group_apps (group_id, app_id) VALUES (?, ?)")
        .bind(group_id)
        .bind(app_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub(super) async fn detach_in(tx: &mut Tx<'_>, group_id: &str, app_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM port_group_apps WHERE group_id = ? AND app_id = ?")
        .bind(group_id)
        .bind(app_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

impl Database {
    pub async fn list_port_groups(&self) -> Result<Vec<PortGroup>> {
        self.load_port_groups(None).await
    }

    pub async fn get_port_group(&self, id: &str) -> Result<Option<PortGroup>> {
        Ok(self.load_port_groups(Some(id)).await?.into_iter().next())
    }

    async fn load_port_groups(&self, only: Option<&str>) -> Result<Vec<PortGroup>> {
        let mut conn = self.pool.acquire().await?;
        Self::load_port_groups_on(&mut conn, only).await
    }

    pub(super) async fn load_port_groups_on(
        conn: &mut sqlx::SqliteConnection,
        only: Option<&str>,
    ) -> Result<Vec<PortGroup>> {
        let rows = sqlx::query(
            "SELECT id, label, ports, created_at FROM port_groups \
             WHERE (?1 IS NULL OR id = ?1) ORDER BY label",
        )
        .bind(only)
        .fetch_all(&mut *conn)
        .await?;
        let mut groups = Vec::with_capacity(rows.len());
        for r in rows {
            groups.push(PortGroup {
                id: r.get("id"),
                label: r.get("label"),
                ports: serde_json::from_str(r.get::<&str, _>("ports"))?,
                apps: Vec::new(),
                created_at: parse_ts(r.get("created_at"))?,
            });
        }
        let attached = sqlx::query(
            "SELECT group_id, app_id FROM port_group_apps \
             WHERE (?1 IS NULL OR group_id = ?1) ORDER BY rowid",
        )
        .bind(only)
        .fetch_all(&mut *conn)
        .await?;
        let mut by_group: HashMap<String, Vec<String>> = HashMap::new();
        for r in attached {
            by_group
                .entry(r.get("group_id"))
                .or_default()
                .push(r.get("app_id"));
        }
        for g in &mut groups {
            g.apps = by_group.remove(&g.id).unwrap_or_default();
        }
        Ok(groups)
    }
}

#[cfg(test)]
mod tests {
    use crate::state::test_util::*;
    use crate::state::{is_unique_violation, Write};
    use socketguard_core::{new_id, parse_ranges, PortGroup};

    fn group(label: &str, ports: &[&str], apps: &[&str]) -> PortGroup {
        PortGroup {
            id: new_id(),
            label: label.into(),
            ports: parse_ranges(ports).unwrap(),
            apps: apps.iter().map(|a| a.to_string()).collect(),
            created_at: now(),
        }
    }

    #[tokio::test]
    async fn port_groups_roundtrip_attach_and_cascade() {
        let db = db().await;
        for a in ["a1", "a2"] {
            db.insert_app(&app(a)).await.unwrap();
        }
        let g = group("passive", &["50000-51000/tcp", "21/tcp"], &["a1"]);
        db.apply_writes(&[Write::InsertPortGroup(g.clone())])
            .await
            .unwrap();
        let got = db.get_port_group(&g.id).await.unwrap().unwrap();
        assert_eq!(got.label, "passive");
        assert_eq!(got.ports, g.ports);
        assert_eq!(got.apps, ["a1"]);

        db.apply_writes(&[
            Write::AttachPortGroup {
                group_id: g.id.clone(),
                app_id: "a2".into(),
            },
            Write::AttachPortGroup {
                group_id: g.id.clone(),
                app_id: "a2".into(),
            },
        ])
        .await
        .unwrap();
        assert_eq!(
            db.get_port_group(&g.id).await.unwrap().unwrap().apps,
            ["a1", "a2"],
            "attaching twice is idempotent"
        );
        db.apply_writes(&[Write::DetachPortGroup {
            group_id: g.id.clone(),
            app_id: "a1".into(),
        }])
        .await
        .unwrap();
        // Deleting an app drops its attachment.
        db.delete_app("a2").await.unwrap();
        assert!(db
            .get_port_group(&g.id)
            .await
            .unwrap()
            .unwrap()
            .apps
            .is_empty());

        db.apply_writes(&[Write::UpdatePortGroup {
            id: g.id.clone(),
            label: Some("ftp".into()),
            ports: Some(parse_ranges(&["2121/tcp"]).unwrap()),
        }])
        .await
        .unwrap();
        let got = db.get_port_group(&g.id).await.unwrap().unwrap();
        assert_eq!((got.label.as_str(), got.ports.len()), ("ftp", 1));
        // Only the given fields change.
        db.apply_writes(&[Write::UpdatePortGroup {
            id: g.id.clone(),
            label: None,
            ports: None,
        }])
        .await
        .unwrap();
        assert_eq!(
            db.get_port_group(&g.id).await.unwrap().unwrap().label,
            "ftp"
        );

        db.apply_writes(&[Write::AttachPortGroup {
            group_id: g.id.clone(),
            app_id: "a1".into(),
        }])
        .await
        .unwrap();
        db.apply_writes(&[Write::DeletePortGroup(g.id.clone())])
            .await
            .unwrap();
        assert_eq!(count(&db, "port_groups").await, 0);
        assert_eq!(count(&db, "port_group_apps").await, 0);
    }

    #[tokio::test]
    async fn labels_are_unique_and_a_failed_batch_changes_nothing() {
        let db = db().await;
        db.apply_writes(&[Write::InsertPortGroup(group("x", &["1/tcp"], &[]))])
            .await
            .unwrap();
        let err = db
            .apply_writes(&[
                Write::InsertPortGroup(group("y", &["2/tcp"], &[])),
                Write::InsertPortGroup(group("x", &["3/tcp"], &[])),
            ])
            .await
            .unwrap_err();
        assert!(is_unique_violation(&err));
        assert_eq!(count(&db, "port_groups").await, 1);
    }

    #[tokio::test]
    async fn a_retire_in_a_failed_batch_is_rolled_back_and_in_a_good_one_kept() {
        let db = db().await;
        let addr: std::net::Ipv6Addr = "300:1::1".parse().unwrap();
        db.claim_address(addr, "ygg0", Some("ygg")).await.unwrap();
        db.apply_writes(&[Write::InsertPortGroup(group("x", &["1/tcp"], &[]))])
            .await
            .unwrap();
        let retire = Write::RetireAddress {
            addr,
            interface: "ygg0".into(),
            network_id: Some("ygg".into()),
        };
        let err = db
            .apply_writes(&[
                retire.clone(),
                Write::InsertPortGroup(group("x", &["3/tcp"], &[])),
            ])
            .await
            .unwrap_err();
        assert!(is_unique_violation(&err));
        assert!(!db.list_owned_addresses().await.unwrap()[0].retiring);
        // A dry run leaves nothing either.
        db.try_writes(std::slice::from_ref(&retire)).await.unwrap();
        assert!(!db.list_owned_addresses().await.unwrap()[0].retiring);
        db.apply_writes(&[retire]).await.unwrap();
        assert!(db.list_owned_addresses().await.unwrap()[0].retiring);
    }
}
