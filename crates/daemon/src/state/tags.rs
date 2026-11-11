//! Tags (ADR 0043), the writes a batch of changes applies in one transaction (ADR 0045)
//! and the Tor client keys the daemon generated.

use super::port_groups::{
    attach_in, delete_port_group_in, detach_in, insert_port_group_in, update_port_group_in,
};
use super::reservations::{
    assign_address_in, delete_reservation_in, insert_binding_in, insert_reservation_in,
};
use super::{
    insert_address_in, insert_grant_in, insert_peer_in, parse_ts, scope_columns,
    scope_from_columns, ts, Database, Tx,
};
use anyhow::Result;
use socketguard_core::{
    Address, App, Binding, Credential, Grant, Peer, PeerGroup, PortGroup, PortRange, Reservation,
    Scope, Tag, TagId, TagMember,
};
use sqlx::Row;
use std::collections::HashMap;

/// One database change. A batch applies a list of these in one transaction.
#[derive(Debug, Clone)]
pub enum Write {
    InsertPeer(Peer),
    /// The group with its members.
    InsertGroup(PeerGroup),
    /// The tag with its members.
    InsertTag(Tag),
    InsertGrant(Grant),
    DeleteGrant(String),
    /// Idempotent; a manual addition clears the app's exclusion.
    AddTagMember {
        tag_id: TagId,
        app_id: String,
        scope: Scope,
    },
    /// Remove one member. With `exclude`, remember the app as excluded so patterns do not
    /// add it back.
    RemoveTagMember {
        tag_id: TagId,
        app_id: String,
        scope: Scope,
        exclude: bool,
    },
    /// The group with its attachments.
    InsertPortGroup(PortGroup),
    UpdatePortGroup {
        id: String,
        label: Option<String>,
        ports: Option<Vec<PortRange>>,
    },
    /// The attachments go with the group.
    DeletePortGroup(String),
    /// Idempotent.
    AttachPortGroup {
        group_id: String,
        app_id: String,
    },
    DetachPortGroup {
        group_id: String,
        app_id: String,
    },
    /// An address and, with it, its onion key.
    DeleteAddress(String),
    /// A new address with its locator secret (the onion service key).
    InsertAddress {
        address: Address,
        secret: Option<String>,
    },
    /// The reservation with its bindings.
    InsertReservation(Reservation),
    RenameReservation {
        id: String,
        label: String,
    },
    /// The reservation, the grants on it, its bindings and its addresses.
    DeleteReservation(String),
    InsertBinding(Binding),
    DeleteBinding(String),
    /// An automatic address becomes the address of a reservation, locator kept.
    AssignAddress {
        address_id: String,
        reservation_id: String,
    },
    /// `move_app`: a grant, an automatic address or a binding of one app goes to another.
    MoveGrant {
        grant_id: String,
        to_app: String,
    },
    MoveAddress {
        address_id: String,
        to_app: String,
    },
    MoveBinding {
        binding_id: String,
        to_app: String,
    },
    SetReviewed {
        app_id: String,
        reviewed: bool,
    },
}

async fn apply_write(tx: &mut Tx<'_>, w: &Write) -> Result<()> {
    match w {
        Write::InsertPeer(p) => insert_peer_in(tx, p).await?,
        Write::InsertGroup(g) => {
            sqlx::query("INSERT INTO peer_groups (id, label, created_at) VALUES (?, ?, ?)")
                .bind(&g.id)
                .bind(&g.label)
                .bind(ts(g.created_at))
                .execute(&mut **tx)
                .await?;
            for m in &g.members {
                sqlx::query("INSERT INTO peer_group_members (group_id, peer_id) VALUES (?, ?)")
                    .bind(&g.id)
                    .bind(m)
                    .execute(&mut **tx)
                    .await?;
            }
        }
        Write::InsertGrant(g) => insert_grant_in(tx, g).await?,
        Write::DeleteGrant(id) => {
            sqlx::query("DELETE FROM grants WHERE id = ?")
                .bind(id)
                .execute(&mut **tx)
                .await?;
        }
        Write::InsertTag(t) => {
            sqlx::query("INSERT INTO tags (id, label, patterns, created_at) VALUES (?, ?, ?, ?)")
                .bind(&t.id)
                .bind(&t.label)
                .bind(serde_json::to_string(&t.patterns)?)
                .bind(ts(t.created_at))
                .execute(&mut **tx)
                .await?;
            for m in &t.members {
                add_member(tx, &t.id, &m.app_id, &m.scope).await?;
            }
        }
        Write::AddTagMember {
            tag_id,
            app_id,
            scope,
        } => {
            add_member(tx, tag_id, app_id, scope).await?;
            sqlx::query("DELETE FROM tag_exclusions WHERE tag_id = ? AND app_id = ?")
                .bind(tag_id)
                .bind(app_id)
                .execute(&mut **tx)
                .await?;
        }
        Write::RemoveTagMember {
            tag_id,
            app_id,
            scope,
            exclude,
        } => {
            let (port, proto, group) = scope_columns(scope);
            sqlx::query(
                "DELETE FROM tag_members WHERE tag_id = ? AND app_id = ? \
                 AND COALESCE(port, -1) = ? AND COALESCE(proto, '') = ? \
                 AND COALESCE(port_group, '') = ?",
            )
            .bind(tag_id)
            .bind(app_id)
            .bind(port.unwrap_or(-1))
            .bind(proto.unwrap_or_default())
            .bind(group.unwrap_or_default())
            .execute(&mut **tx)
            .await?;
            if *exclude {
                sqlx::query("INSERT OR IGNORE INTO tag_exclusions (tag_id, app_id) VALUES (?, ?)")
                    .bind(tag_id)
                    .bind(app_id)
                    .execute(&mut **tx)
                    .await?;
            }
        }
        Write::InsertPortGroup(g) => insert_port_group_in(tx, g).await?,
        Write::UpdatePortGroup { id, label, ports } => {
            update_port_group_in(tx, id, label.as_deref(), ports.as_deref()).await?
        }
        Write::DeletePortGroup(id) => delete_port_group_in(tx, id).await?,
        Write::AttachPortGroup { group_id, app_id } => attach_in(tx, group_id, app_id).await?,
        Write::DetachPortGroup { group_id, app_id } => detach_in(tx, group_id, app_id).await?,
        Write::DeleteAddress(id) => {
            sqlx::query("DELETE FROM addresses WHERE id = ?")
                .bind(id)
                .execute(&mut **tx)
                .await?;
        }
        Write::InsertAddress { address, secret } => {
            insert_address_in(tx, address, secret.as_deref()).await?
        }
        Write::InsertReservation(r) => insert_reservation_in(tx, r).await?,
        Write::RenameReservation { id, label } => {
            sqlx::query("UPDATE reservations SET label = ? WHERE id = ?")
                .bind(label)
                .bind(id)
                .execute(&mut **tx)
                .await?;
        }
        Write::DeleteReservation(id) => {
            delete_reservation_in(tx, id).await?;
        }
        Write::InsertBinding(b) => insert_binding_in(tx, b).await?,
        Write::DeleteBinding(id) => {
            sqlx::query("DELETE FROM reservation_bindings WHERE id = ?")
                .bind(id)
                .execute(&mut **tx)
                .await?;
        }
        Write::AssignAddress {
            address_id,
            reservation_id,
        } => assign_address_in(tx, address_id, reservation_id).await?,
        Write::MoveGrant { grant_id, to_app } => {
            sqlx::query("UPDATE grants SET target_id = ? WHERE id = ? AND target_kind = 'app'")
                .bind(to_app)
                .bind(grant_id)
                .execute(&mut **tx)
                .await?;
        }
        Write::MoveAddress { address_id, to_app } => {
            sqlx::query("UPDATE addresses SET app_id = ? WHERE id = ?")
                .bind(to_app)
                .bind(address_id)
                .execute(&mut **tx)
                .await?;
        }
        Write::MoveBinding { binding_id, to_app } => {
            sqlx::query("UPDATE reservation_bindings SET app_id = ? WHERE id = ?")
                .bind(to_app)
                .bind(binding_id)
                .execute(&mut **tx)
                .await?;
        }
        Write::SetReviewed { app_id, reviewed } => {
            sqlx::query("UPDATE apps SET reviewed = ? WHERE id = ?")
                .bind(reviewed)
                .bind(app_id)
                .execute(&mut **tx)
                .await?;
        }
    }
    Ok(())
}

async fn add_member(tx: &mut Tx<'_>, tag_id: &str, app_id: &str, scope: &Scope) -> Result<()> {
    let (port, proto, group) = scope_columns(scope);
    sqlx::query(
        "INSERT OR IGNORE INTO tag_members (tag_id, app_id, port, proto, port_group) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(tag_id)
    .bind(app_id)
    .bind(port)
    .bind(proto)
    .bind(group)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

impl Database {
    /// Apply `writes` in one transaction: all or nothing.
    pub async fn apply_writes(&self, writes: &[Write]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        for w in writes {
            apply_write(&mut tx, w).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Run `writes` against the real constraints, then roll everything back.
    pub async fn try_writes(&self, writes: &[Write]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        for w in writes {
            apply_write(&mut tx, w).await?;
        }
        tx.rollback().await?;
        Ok(())
    }

    // ======== Tags ========

    pub async fn list_tags(&self) -> Result<Vec<Tag>> {
        self.load_tags(None).await
    }

    pub async fn get_tag(&self, id: &str) -> Result<Option<Tag>> {
        Ok(self.load_tags(Some(id)).await?.into_iter().next())
    }

    async fn load_tags(&self, only: Option<&str>) -> Result<Vec<Tag>> {
        let rows = sqlx::query(
            "SELECT id, label, patterns, created_at FROM tags WHERE (?1 IS NULL OR id = ?1) \
             ORDER BY label",
        )
        .bind(only)
        .fetch_all(&self.pool)
        .await?;
        let mut tags = Vec::with_capacity(rows.len());
        for r in rows {
            tags.push(Tag {
                id: r.get("id"),
                label: r.get("label"),
                patterns: serde_json::from_str(r.get::<&str, _>("patterns"))?,
                members: Vec::new(),
                excluded: Vec::new(),
                created_at: parse_ts(r.get("created_at"))?,
            });
        }
        let members = sqlx::query(
            "SELECT tag_id, app_id, port, proto, port_group FROM tag_members \
             WHERE (?1 IS NULL OR tag_id = ?1) ORDER BY rowid",
        )
        .bind(only)
        .fetch_all(&self.pool)
        .await?;
        let mut by_tag: HashMap<String, Vec<TagMember>> = HashMap::new();
        for r in members {
            let scope = scope_from_columns(r.get("port"), r.get("proto"), r.get("port_group"))?;
            by_tag.entry(r.get("tag_id")).or_default().push(TagMember {
                app_id: r.get("app_id"),
                scope,
            });
        }
        let excluded = sqlx::query(
            "SELECT tag_id, app_id FROM tag_exclusions WHERE (?1 IS NULL OR tag_id = ?1) \
             ORDER BY rowid",
        )
        .bind(only)
        .fetch_all(&self.pool)
        .await?;
        let mut ex_by_tag: HashMap<String, Vec<String>> = HashMap::new();
        for r in excluded {
            ex_by_tag
                .entry(r.get("tag_id"))
                .or_default()
                .push(r.get("app_id"));
        }
        for t in &mut tags {
            t.members = by_tag.remove(&t.id).unwrap_or_default();
            t.excluded = ex_by_tag.remove(&t.id).unwrap_or_default();
        }
        Ok(tags)
    }

    /// Change a tag's label and/or patterns. False if the tag does not exist.
    pub async fn update_tag(
        &self,
        id: &str,
        label: Option<&str>,
        patterns: Option<&[String]>,
    ) -> Result<bool> {
        let patterns = patterns.map(serde_json::to_string).transpose()?;
        let r = sqlx::query(
            "UPDATE tags SET label = COALESCE(?, label), patterns = COALESCE(?, patterns) \
             WHERE id = ?",
        )
        .bind(label)
        .bind(patterns)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Delete a tag with its members, exclusions and the grants that target it.
    pub async fn delete_tag(&self, id: &str) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM grants WHERE target_kind = 'tag' AND target_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let r = sqlx::query("DELETE FROM tags WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(r.rows_affected() > 0)
    }

    /// Put `app` into every tag whose patterns match it and that has not excluded it.
    /// Returns the ids of the tags it newly joined.
    pub async fn auto_tag_app(&self, app: &App) -> Result<Vec<TagId>> {
        let mut joined = Vec::new();
        for tag in self.list_tags().await? {
            if !tag.matches(app) || tag.excluded.contains(&app.id) {
                continue;
            }
            if tag.members.iter().any(|m| m.app_id == app.id) {
                continue;
            }
            let mut tx = self.pool.begin().await?;
            add_member(&mut tx, &tag.id, &app.id, &Scope::All).await?;
            tx.commit().await?;
            joined.push(tag.id);
        }
        Ok(joined)
    }

    // ======== Tor client keys ========

    /// The private keys of generated Tor client keys, by credential id.
    pub async fn tor_client_keys(&self) -> Result<HashMap<String, String>> {
        Ok(sqlx::query_as::<_, (String, String)>(
            "SELECT credential_id, private_key FROM tor_client_keys",
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .collect())
    }

    /// Give `peer_id` a freshly generated Tor client key, replacing the ones the daemon
    /// generated before (a key the user pasted stays). Returns the ids of the credentials
    /// that were replaced.
    pub async fn replace_generated_tor_key(
        &self,
        peer_id: &str,
        credential: &Credential,
        private_key: &str,
    ) -> Result<Vec<String>> {
        let mut tx = self.pool.begin().await?;
        let old: Vec<String> = sqlx::query_scalar(
            "SELECT c.id FROM peer_credentials c JOIN tor_client_keys k ON k.credential_id = c.id \
             WHERE c.peer_id = ?",
        )
        .bind(peer_id)
        .fetch_all(&mut *tx)
        .await?;
        for id in &old {
            // The key row goes with its credential (ON DELETE CASCADE).
            sqlx::query("DELETE FROM peer_credentials WHERE id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        super::insert_credential(&mut tx, peer_id, credential).await?;
        sqlx::query("INSERT INTO tor_client_keys (credential_id, private_key) VALUES (?, ?)")
            .bind(&credential.id)
            .bind(private_key)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(old)
    }
}

#[cfg(test)]
mod tests {
    use crate::state::test_util::*;
    use crate::state::{is_unique_violation, Write};
    use chrono::Utc;
    use socketguard_core::{new_id, CredentialKind, Scope, Subject, Tag, TagMember, Target};

    fn tag(label: &str, patterns: &[&str], members: Vec<TagMember>) -> Tag {
        Tag {
            id: new_id(),
            label: label.into(),
            patterns: patterns.iter().map(|s| s.to_string()).collect(),
            members,
            excluded: vec![],
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn tags_roundtrip_with_members_and_exclusions() {
        let db = db().await;
        db.insert_app(&app("a")).await.unwrap();
        db.insert_app(&app("b")).await.unwrap();
        let t = tag(
            "dev",
            &["py*"],
            vec![TagMember {
                app_id: "a".into(),
                scope: Scope::All,
            }],
        );
        db.apply_writes(&[Write::InsertTag(t.clone())])
            .await
            .unwrap();
        db.apply_writes(&[
            Write::AddTagMember {
                tag_id: t.id.clone(),
                app_id: "b".into(),
                scope: Scope::Port {
                    port: 80,
                    proto: socketguard_core::Protocol::Tcp,
                },
            },
            Write::RemoveTagMember {
                tag_id: t.id.clone(),
                app_id: "a".into(),
                scope: Scope::All,
                exclude: true,
            },
        ])
        .await
        .unwrap();
        let got = db.get_tag(&t.id).await.unwrap().unwrap();
        assert_eq!(got.patterns, ["py*"]);
        assert_eq!(got.members.len(), 1);
        assert_eq!(got.members[0].app_id, "b");
        assert_eq!(got.excluded, ["a"]);
        // A manual re-add clears the exclusion.
        db.apply_writes(&[Write::AddTagMember {
            tag_id: t.id.clone(),
            app_id: "a".into(),
            scope: Scope::All,
        }])
        .await
        .unwrap();
        assert!(db
            .get_tag(&t.id)
            .await
            .unwrap()
            .unwrap()
            .excluded
            .is_empty());
        // Adding twice is a no-op.
        db.apply_writes(&[Write::AddTagMember {
            tag_id: t.id.clone(),
            app_id: "a".into(),
            scope: Scope::All,
        }])
        .await
        .unwrap();
        assert_eq!(db.get_tag(&t.id).await.unwrap().unwrap().members.len(), 2);

        let dup = tag("dev", &[], vec![]);
        let err = db.apply_writes(&[Write::InsertTag(dup)]).await.unwrap_err();
        assert!(is_unique_violation(&err));
    }

    #[tokio::test]
    async fn members_by_scope_are_distinct_and_removed_by_scope() {
        let db = db().await;
        db.insert_app(&app("a")).await.unwrap();
        let t = tag("dev", &[], vec![]);
        db.apply_writes(&[Write::InsertTag(t.clone())])
            .await
            .unwrap();
        let scopes = [
            Scope::All,
            Scope::Port {
                port: 80,
                proto: socketguard_core::Protocol::Tcp,
            },
            Scope::Group { id: "sg".into() },
        ];
        for scope in &scopes {
            db.apply_writes(&[Write::AddTagMember {
                tag_id: t.id.clone(),
                app_id: "a".into(),
                scope: scope.clone(),
            }])
            .await
            .unwrap();
        }
        let got: Vec<Scope> = db
            .get_tag(&t.id)
            .await
            .unwrap()
            .unwrap()
            .members
            .into_iter()
            .map(|m| m.scope)
            .collect();
        assert_eq!(got, scopes);
        db.apply_writes(&[Write::RemoveTagMember {
            tag_id: t.id.clone(),
            app_id: "a".into(),
            scope: scopes[2].clone(),
            exclude: false,
        }])
        .await
        .unwrap();
        assert_eq!(db.get_tag(&t.id).await.unwrap().unwrap().members.len(), 2);
    }

    #[tokio::test]
    async fn deleting_a_tag_or_an_app_deletes_its_grants() {
        let db = db().await;
        db.insert_app(&app("a")).await.unwrap();
        let t = tag("dev", &[], vec![]);
        db.apply_writes(&[Write::InsertTag(t.clone())])
            .await
            .unwrap();
        let mut g = grant("a", Subject::Anyone);
        g.target = Target::Tag(t.id.clone());
        db.insert_grant(&g).await.unwrap();
        db.insert_grant(&grant("a", Subject::Anyone)).await.unwrap();
        // The unique index covers the target kind and id.
        let err = db.insert_grant(&g).await.unwrap_err();
        assert!(is_unique_violation(&err));
        assert!(db.delete_tag(&t.id).await.unwrap());
        assert_eq!(count(&db, "grants").await, 1);
        assert!(db.delete_app("a").await.unwrap());
        assert_eq!(count(&db, "grants").await, 0);
    }

    #[tokio::test]
    async fn a_failing_write_rolls_the_whole_batch_back() {
        let db = db().await;
        let p = peer("alice", &[]);
        let dup = peer("alice", &[]);
        let err = db
            .apply_writes(&[Write::InsertPeer(p), Write::InsertPeer(dup)])
            .await
            .unwrap_err();
        assert!(is_unique_violation(&err));
        assert_eq!(count(&db, "peers").await, 0);
        // A dry run runs the writes and leaves nothing.
        db.try_writes(&[Write::InsertPeer(peer("bob", &[]))])
            .await
            .unwrap();
        assert_eq!(count(&db, "peers").await, 0);
    }

    #[tokio::test]
    async fn auto_tag_respects_patterns_and_exclusions() {
        let db = db().await;
        let mut a = app("a");
        a.process_name = "python3".into();
        db.insert_app(&a).await.unwrap();
        let t = tag("py", &["python*"], vec![]);
        db.apply_writes(&[Write::InsertTag(t.clone())])
            .await
            .unwrap();
        assert_eq!(
            db.auto_tag_app(&a).await.unwrap(),
            std::slice::from_ref(&t.id)
        );
        assert!(db.auto_tag_app(&a).await.unwrap().is_empty(), "once");
        db.apply_writes(&[Write::RemoveTagMember {
            tag_id: t.id.clone(),
            app_id: "a".into(),
            scope: Scope::All,
            exclude: true,
        }])
        .await
        .unwrap();
        assert!(db.auto_tag_app(&a).await.unwrap().is_empty(), "excluded");
    }

    #[tokio::test]
    async fn regenerating_a_tor_key_replaces_only_generated_ones() {
        use socketguard_core::Credential;
        let db = db().await;
        let pasted = socketguard_core::new_id();
        let mut p = peer("alice", &[]);
        p.credentials.push(Credential {
            id: pasted.clone(),
            kind: CredentialKind::TorClientKey,
            value: "PASTED".into(),
            label: None,
        });
        db.insert_peer(&p).await.unwrap();
        let cred = |v: &str| Credential {
            id: new_id(),
            kind: CredentialKind::TorClientKey,
            value: v.into(),
            label: None,
        };
        let first = cred("ONE");
        assert!(db
            .replace_generated_tor_key(&p.id, &first, "priv1")
            .await
            .unwrap()
            .is_empty());
        let second = cred("TWO");
        let replaced = db
            .replace_generated_tor_key(&p.id, &second, "priv2")
            .await
            .unwrap();
        assert_eq!(replaced, std::slice::from_ref(&first.id));
        let keys = db.tor_client_keys().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[&second.id], "priv2");
        let creds = db.get_peer(&p.id).await.unwrap().unwrap().credentials;
        assert_eq!(creds.len(), 2, "the pasted key and the new one");
        // Deleting the peer deletes the key.
        db.delete_peer(&p.id).await.unwrap();
        assert!(db.tor_client_keys().await.unwrap().is_empty());
    }
}
