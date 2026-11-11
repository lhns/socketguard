//! What a removal found and did, per item: removed, already absent, or LEFT with the reason.
//! `--disable` and `uninstall` print it and exit non-zero when anything is left. Nothing is
//! reported as removed unless the removal was confirmed.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Removed,
    Absent,
    /// Deliberately not removed, and why (it existed before SocketGuard, or data was kept).
    Kept(String),
    /// Still there, and why.
    Left(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub what: String,
    pub outcome: Outcome,
    /// Something to add to the line (e.g. "not re-verified").
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub items: Vec<Item>,
    /// Lines that are not items (what could not be checked).
    pub notes: Vec<String>,
}

impl Report {
    pub fn add(&mut self, what: impl Into<String>, outcome: Outcome) {
        self.items.push(Item {
            what: what.into(),
            outcome,
            note: None,
        });
    }
    pub fn removed(&mut self, what: impl Into<String>) {
        self.add(what, Outcome::Removed);
    }
    pub fn absent(&mut self, what: impl Into<String>) {
        self.add(what, Outcome::Absent);
    }
    pub fn kept(&mut self, what: impl Into<String>, why: impl Into<String>) {
        self.add(what, Outcome::Kept(why.into()));
    }
    pub fn left(&mut self, what: impl Into<String>, why: impl Into<String>) {
        self.add(what, Outcome::Left(why.into()));
    }
    pub fn note(&mut self, line: impl Into<String>) {
        self.notes.push(line.into());
    }
    pub fn extend(&mut self, other: Report) {
        self.items.extend(other.items);
        self.notes.extend(other.notes);
    }
    pub fn left_items(&self) -> Vec<&Item> {
        self.items
            .iter()
            .filter(|i| matches!(i.outcome, Outcome::Left(_)))
            .collect()
    }
    /// Nothing is left.
    pub fn complete(&self) -> bool {
        self.left_items().is_empty()
    }
    pub fn render(&self) -> String {
        let mut out = String::new();
        for i in &self.items {
            let note = i.note.as_deref().map(|n| format!(" ({n})")).unwrap_or_default();
            match &i.outcome {
                Outcome::Removed => out.push_str(&format!("removed         {}{note}\n", i.what)),
                Outcome::Absent => out.push_str(&format!("already absent  {}{note}\n", i.what)),
                Outcome::Kept(why) => {
                    out.push_str(&format!("kept            {}: {why}{note}\n", i.what))
                }
                Outcome::Left(why) => {
                    out.push_str(&format!("LEFT            {}: {why}{note}\n", i.what))
                }
            }
        }
        for n in &self.notes {
            out.push_str(&format!("note            {n}\n"));
        }
        let left = self.left_items().len();
        if left > 0 {
            out.push_str(&format!("{left} item(s) LEFT.\n"));
        }
        out
    }
    /// The error to return when something is left.
    pub fn into_result(self) -> anyhow::Result<()> {
        let left: Vec<String> = self
            .left_items()
            .iter()
            .map(|i| match &i.outcome {
                Outcome::Left(why) => format!("{}: {why}", i.what),
                _ => unreachable!(),
            })
            .collect();
        if left.is_empty() {
            Ok(())
        } else {
            anyhow::bail!("{} item(s) left: {}", left.len(), left.join("; "))
        }
    }
}
