//! The third-party programs this build ships (ADR 0052): Tor, Yggdrasil and, on Windows,
//! the Wintun driver, in a `third_party` directory next to the daemon executable.
//! Only locating and describing them lives here; running them is the networks' business.

use socketguard_core::setup::{BundledInfo, NOT_INCLUDED};
use std::path::{Path, PathBuf};

/// Overrides the lookup next to the executable (development, tests).
pub const THIRD_PARTY_ENV: &str = "SOCKETGUARD_THIRD_PARTY";

const EXE: &str = if cfg!(windows) { ".exe" } else { "" };

/// Where packages put the files, when they are not next to the executable (Windows: only
/// next to it).
const PACKAGED: Option<&str> = if cfg!(target_os = "linux") {
    Some("/usr/lib/socketguard/third_party")
} else if cfg!(target_os = "macos") {
    Some("/usr/local/lib/socketguard/third_party")
} else {
    None
};

/// The places to look, in order.
fn candidates(exe_dir: Option<&Path>, env: Option<PathBuf>) -> Vec<PathBuf> {
    exe_dir
        .map(|d| d.join("third_party"))
        .into_iter()
        .chain(PACKAGED.map(PathBuf::from))
        .chain(env)
        .collect()
}

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
    /// The first existing of [`candidates`]: next to the daemon executable, the packaged
    /// location of the platform, `$SOCKETGUARD_THIRD_PARTY`.
    pub fn locate() -> Self {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(Path::to_path_buf));
        let env = std::env::var_os(THIRD_PARTY_ENV).map(PathBuf::from);
        Self::first_existing(&candidates(exe_dir.as_deref(), env))
    }

    /// The first of `list` that is a directory.
    fn first_existing(list: &[PathBuf]) -> Self {
        Self {
            dir: list.iter().find(|d| d.is_dir()).cloned(),
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
    fn the_lookup_order_is_beside_the_executable_then_packaged_then_the_variable() {
        let list = candidates(Some(Path::new("/opt/sg")), Some("/dev/tp".into()));
        assert_eq!(list[0], Path::new("/opt/sg").join("third_party"));
        assert_eq!(list.last().unwrap(), Path::new("/dev/tp"));
        match PACKAGED {
            Some(p) => assert_eq!(list[1], Path::new(p)),
            None => assert_eq!(list.len(), 2, "Windows: next to the executable only"),
        }
        assert_eq!(
            candidates(None, None).len(),
            usize::from(PACKAGED.is_some())
        );

        let (a, b) = (temp(), temp());
        let missing = a.join("nope");
        // The first that exists wins; missing ones are skipped.
        let pick = |l: &[PathBuf]| Bundled::first_existing(l).dir().map(Path::to_path_buf);
        assert_eq!(pick(&[missing.clone(), a.clone(), b.clone()]), Some(a));
        assert_eq!(pick(&[missing.clone(), b.clone()]), Some(b));
        assert_eq!(pick(&[missing]), None);
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
