//! The export document as text: TOML or JSON, written by `export` and read by `apply`.

use anyhow::{anyhow, Context, Result};
use socketguard_core::api_types::ExportDocument;

/// The document as TOML or JSON.
pub fn text(doc: &ExportDocument, json: bool) -> Result<String> {
    if json {
        Ok(serde_json::to_string_pretty(doc)? + "\n")
    } else {
        Ok(toml::to_string_pretty(doc).context("cannot write TOML")?)
    }
}

/// Parse a document; the extension picks the format, else TOML and then JSON are tried.
pub fn parse(text: &str, path: &std::path::Path) -> Result<ExportDocument> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("json") => Ok(serde_json::from_str(text).context("invalid JSON document")?),
        Some("toml") => Ok(toml::from_str(text).context("invalid TOML document")?),
        _ => toml::from_str(text).or_else(|toml_err| {
            serde_json::from_str(text).map_err(|json_err| {
                anyhow!("not a TOML document ({toml_err}) nor a JSON one ({json_err})")
            })
        }),
    }
}
