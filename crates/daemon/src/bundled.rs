//! The third-party programs this build ships (ADR 0052): Tor, Yggdrasil and, on Windows,
//! the Wintun driver, in a `third_party` directory next to the daemon executable.
//! Only locating and describing them lives here; running them is the networks' business.

use socketguard_core::setup::{BundledInfo, NOT_INCLUDED};
use std::path::{Path, PathBuf};

/// Overrides the lookup next to the executable (development, tests).
pub const THIRD_PARTY_ENV: &str = "SOCKETGUARD_THIRD_PARTY";

const EXE: &str = if cfg!(windows) { ".exe" } else { "" };

/// The Tor files: the binary, and the directory it lives in (its libraries and data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorFiles {
    pub binary: PathBuf,
    pub dir: PathBuf,
}

/// The Yggdrasil files. On Windows `wintun.dll` sits next to the binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YggFiles {
    pub binary: PathBuf,
    pub dir: PathBuf,
}

/// The located `third_party` directory, or none: then managed networks are not included.
#[derive(Debug, Clone, Default)]
pub struct Bundled {
    dir: Option<PathBuf>,
}

impl Bundled {
    /// `<daemon executable directory>/third_party`, else `$SOCKETGUARD_THIRD_PARTY`.
    pub fn locate() -> Self {
        let beside = std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|d| d.join("third_party")))
            .filter(|d| d.is_dir());
        let from_env = std::env::var_os(THIRD_PARTY_ENV)
            .map(PathBuf::from)
            .filter(|d| d.is_dir());
        Self {
            dir: beside.or(from_env),
        }
    }

    /// A build without the files.
    pub fn none() -> Self {
        Self { dir: None }
    }

    /// Use `dir` as the `third_party` directory (tests).
    pub fn from_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: Some(dir.into()),
        }
    }

    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }

    /// The directory and the versions listed in `VERSIONS`.
    pub fn info(&self) -> BundledInfo {
        let Some(dir) = &self.dir else {
            return BundledInfo::default();
        };
        let versions = std::fs::read_to_string(dir.join("VERSIONS"))
            .map(|t| BundledInfo::parse_versions(&t))
            .unwrap_or_default();
        BundledInfo {
            dir: Some(dir.display().to_string()),
            versions,
        }
    }

    /// The shipped version of `name` (`tor`, `yggdrasil`, `wintun`).
    pub fn version_of(&self, name: &str) -> Option<String> {
        self.info().version_of(name).map(str::to_string)
    }

    pub fn tor(&self) -> Result<TorFiles, String> {
        let dir = self.dir.as_ref().ok_or_else(|| NOT_INCLUDED.to_string())?;
        let tor_dir = dir.join("tor");
        let binary = tor_dir.join(format!("tor{EXE}"));
        if !binary.is_file() {
            return Err("the Tor files of this build are incomplete: tor is missing".into());
        }
        Ok(TorFiles {
            binary,
            dir: tor_dir,
        })
    }

    pub fn yggdrasil(&self) -> Result<YggFiles, String> {
        let dir = self.dir.as_ref().ok_or_else(|| NOT_INCLUDED.to_string())?;
        let ygg_dir = dir.join("yggdrasil");
        let binary = ygg_dir.join(format!("yggdrasil{EXE}"));
        let incomplete = |what: &str| {
            format!("the Yggdrasil files of this build are incomplete: {what} is missing")
        };
        if !binary.is_file() {
            return Err(incomplete("yggdrasil"));
        }
        if cfg!(windows) && !ygg_dir.join("wintun.dll").is_file() {
            return Err(incomplete("wintun.dll"));
        }
        Ok(YggFiles {
            binary,
            dir: ygg_dir,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("sg-bundled-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn touch(p: &Path) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, b"x").unwrap();
    }

    #[test]
    fn no_directory_means_not_included() {
        let b = Bundled::none();
        assert_eq!(b.tor().unwrap_err(), NOT_INCLUDED);
        assert_eq!(b.yggdrasil().unwrap_err(), NOT_INCLUDED);
        assert_eq!(b.info(), BundledInfo::default());
        assert_eq!(b.version_of("tor"), None);
    }

    #[test]
    fn missing_files_are_reported_in_a_sentence() {
        let d = temp();
        let b = Bundled::from_dir(&d);
        assert_eq!(
            b.tor().unwrap_err(),
            "the Tor files of this build are incomplete: tor is missing"
        );
        assert!(b.yggdrasil().unwrap_err().contains("yggdrasil is missing"));
    }

    #[test]
    fn complete_files_are_found_with_versions() {
        let root = temp();
        let root = root.as_path();
        touch(&root.join("tor").join(format!("tor{EXE}")));
        touch(&root.join("yggdrasil").join(format!("yggdrasil{EXE}")));
        let b = Bundled::from_dir(root);
        assert_eq!(b.tor().unwrap().dir, root.join("tor"));
        if cfg!(windows) {
            assert!(b.yggdrasil().unwrap_err().contains("wintun.dll"));
            touch(&root.join("yggdrasil").join("wintun.dll"));
        }
        assert_eq!(
            b.yggdrasil().unwrap().binary,
            root.join("yggdrasil").join(format!("yggdrasil{EXE}"))
        );
        std::fs::write(root.join("VERSIONS"), "tor 16.0.1\nyggdrasil v0.5.15 abc\n").unwrap();
        assert_eq!(b.version_of("tor").as_deref(), Some("16.0.1"));
        assert_eq!(
            b.info().dir.as_deref(),
            Some(root.display().to_string().as_str())
        );
        assert_eq!(b.info().versions.len(), 2);
    }
}
