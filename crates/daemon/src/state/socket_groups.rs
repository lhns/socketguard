//! Socket groups (ADR 0047): named port sets that are attached to apps and then usable as
//! a scope. Changes go through [`super::Write`] so a batch applies them in one transaction.

use super::{parse_ts, ts, Database, Tx};
use anyhow::Result;
use socketguard_core::{PortRange, SocketGroup};
use sqlx::Row;
use std::collections::HashMap;

pub(super) async fn insert_socket_group_in(tx: &mut Tx<'_>, g: &SocketGroup) -> Result<()> {
    sqlx::query("INSERT INTO socket_groups (id, label, ports, created_at) VALUES (?, ?, ?, ?)")
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

pub(super) async fn update_socket_group_in(
    tx: &mut Tx<'_>,
    id: &str,
    label: Option<&str>,
    ports: Option<&[PortRange]>,
) -> Result<()> {
    let ports = ports.map(serde_json::to_string).transpose()?;
    sqlx::query(
        "UPDATE socket_groups SET label = COALESCE(?, label), ports = COALESCE(?, ports) \
         WHERE id = ?",
    )
    .bind(label)
    .bind(ports)
    .bind(id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(super) async fn delete_socket_group_in(tx: &mut Tx<'_>, id: &str) -> Result<()> {
    // The attachments go with it (ON DELETE CASCADE).
    sqlx::query("DELETE FROM socket_groups WHERE id = ?")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub(super) async fn attach_in(tx: &mut Tx<'_>, group_id: &str, app_id: &str) -> Result<()> {
    sqlx::query("INSERT OR IGNORE INTO socket_group_apps (group_id, app_id) VALUES (?, ?)")
        .bind(group_id)
        .bind(app_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub(super) async fn detach_in(tx: &mut Tx<'_>, group_id: &str, app_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM socket_group_apps WHERE group_id = ? AND app_id = ?")
        .bind(group_id)
        .bind(app_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

impl Database {
    pub async fn list_socket_groups(&self) -> Result<Vec<SocketGroup>> {
        self.load_socket_groups(None).await
    }

    pub async fn get_socket_group(&self, id: &str) -> Result<Option<SocketGroup>> {
        Ok(self.load_socket_groups(Some(id)).await?.into_iter().next())
    }

    async fn load_socket_groups(&self, only: Option<&str>) -> Result<Vec<SocketGroup>> {
        let rows = sqlx::query(
            "SELECT id, label, ports, created_at FROM socket_groups \
             WHERE (?1 IS NULL OR id = ?1) ORDER BY label",
        )
        .bind(only)
        .fetch_all(&self.pool)
        .await?;
        let mut groups = Vec::with_capacity(rows.len());
        for r in rows {
            groups.push(SocketGroup {
                id: r.get("id"),
                label: r.get("label"),
                ports: serde_json::from_str(r.get::<&str, _>("ports"))?,
                apps: Vec::new(),
                created_at: parse_ts(r.get("created_at"))?,
            });
        }
        let attached = sqlx::query(
            "SELECT group_id, app_id FROM socket_group_apps \
             WHERE (?1 IS NULL OR group_id = ?1) ORDER BY rowid",
        )
        .bind(only)
        .fetch_all(&self.pool)
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
    use socketguard_core::{new_id, parse_ranges, SocketGroup};

    fn group(label: &str, ports: &[&str], apps: &[&str]) -> SocketGroup {
        SocketGroup {
            id: new_id(),
            label: label.into(),
            ports: parse_ranges(ports).unwrap(),
            apps: apps.iter().map(|a| a.to_string()).collect(),
            created_at: now(),
        }
    }

    #[tokio::test]
    async fn socket_groups_roundtrip_attach_and_cascade() {
        let db = db().await;
        for a in ["a1", "a2"] {
            db.insert_app(&app(a)).await.unwrap();
        }
        let g = group("passive", &["50000-51000/tcp", "21/tcp"], &["a1"]);
        db.apply_writes(&[Write::InsertSocketGroup(g.clone())])
            .await
            .unwrap();
        let got = db.get_socket_group(&g.id).await.unwrap().unwrap();
        assert_eq!(got.label, "passive");
        assert_eq!(got.ports, g.ports);
        assert_eq!(got.apps, ["a1"]);

        db.apply_writes(&[
            Write::AttachSocketGroup {
                group_id: g.id.clone(),
                app_id: "a2".into(),
            },
            Write::AttachSocketGroup {
                group_id: g.id.clone(),
                app_id: "a2".into(),
            },
        ])
        .await
        .unwrap();
        assert_eq!(
            db.get_socket_group(&g.id).await.unwrap().unwrap().apps,
            ["a1", "a2"],
            "attaching twice is idempotent"
        );
        db.apply_writes(&[Write::DetachSocketGroup {
            group_id: g.id.clone(),
            app_id: "a1".into(),
        }])
        .await
        .unwrap();
        // Deleting an app drops its attachment.
        db.delete_app("a2").await.unwrap();
        assert!(db
            .get_socket_group(&g.id)
            .await
            .unwrap()
            .unwrap()
            .apps
            .is_empty());

        db.apply_writes(&[Write::UpdateSocketGroup {
            id: g.id.clone(),
            label: Some("ftp".into()),
            ports: Some(parse_ranges(&["2121/tcp"]).unwrap()),
        }])
        .await
        .unwrap();
        let got = db.get_socket_group(&g.id).await.unwrap().unwrap();
        assert_eq!((got.label.as_str(), got.ports.len()), ("ftp", 1));
        // Only the given fields change.
        db.apply_writes(&[Write::UpdateSocketGroup {
            id: g.id.clone(),
            label: None,
            ports: None,
        }])
        .await
        .unwrap();
        assert_eq!(
            db.get_socket_group(&g.id).await.unwrap().unwrap().label,
            "ftp"
        );

        db.apply_writes(&[Write::AttachSocketGroup {
            group_id: g.id.clone(),
            app_id: "a1".into(),
        }])
        .await
        .unwrap();
        db.apply_writes(&[Write::DeleteSocketGroup(g.id.clone())])
            .await
            .unwrap();
        assert_eq!(count(&db, "socket_groups").await, 0);
        assert_eq!(count(&db, "socket_group_apps").await, 0);
    }

    #[tokio::test]
    async fn labels_are_unique_and_a_failed_batch_changes_nothing() {
        let db = db().await;
        db.apply_writes(&[Write::InsertSocketGroup(group("x", &["1/tcp"], &[]))])
            .await
            .unwrap();
        let err = db
            .apply_writes(&[
                Write::InsertSocketGroup(group("y", &["2/tcp"], &[])),
                Write::InsertSocketGroup(group("x", &["3/tcp"], &[])),
            ])
            .await
            .unwrap_err();
        assert!(is_unique_violation(&err));
        assert_eq!(count(&db, "socket_groups").await, 1);
    }
}
