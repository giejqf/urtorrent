// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Path sanitisation — a security boundary (AGENTS.md 5.4). Torrent file paths
//! come from untrusted `.torrent` files and must never be able to escape the
//! download directory. Sanitisation happens exactly once, here, in `metainfo`.

use std::path::{Component, Path, PathBuf};

use crate::Error;

/// Maximum length (bytes) of a single path component after sanitisation.
const MAX_COMPONENT: usize = 255;
/// Maximum number of components in one file path.
const MAX_COMPONENTS: usize = 256;
/// Maximum total path length (bytes), summed over components.
const MAX_PATH_BYTES: usize = 4096;

/// A validated relative path: a non-empty sequence of safe components that,
/// joined, stays within the download root. Guaranteed to contain no `.`, `..`,
/// absolute prefix, NUL, separator-in-component, or reserved name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafePath {
    components: Vec<String>,
}

impl SafePath {
    /// Validate a `path` list from a `.torrent` (each element is one component).
    /// `index` is the file's position, used only in error messages.
    pub fn from_components(raw: &[&[u8]], index: usize) -> Result<SafePath, Error> {
        if raw.is_empty() {
            return Err(Error::Path {
                index,
                reason: "empty path",
            });
        }
        if raw.len() > MAX_COMPONENTS {
            return Err(Error::Path {
                index,
                reason: "too many path components",
            });
        }
        let mut components = Vec::with_capacity(raw.len());
        let mut total = 0usize;
        for &c in raw {
            let comp = sanitise_component(c).ok_or(Error::Path {
                index,
                reason: "unsafe path component",
            })?;
            total += comp.len();
            if total > MAX_PATH_BYTES {
                return Err(Error::Path {
                    index,
                    reason: "path too long",
                });
            }
            components.push(comp);
        }
        Ok(SafePath { components })
    }

    /// A single-component safe path from the torrent `name` (single-file
    /// torrents) or the top-level directory name.
    pub fn single(name: &[u8]) -> Result<SafePath, Error> {
        let comp = sanitise_component(name).ok_or(Error::Path {
            index: 0,
            reason: "unsafe torrent name",
        })?;
        Ok(SafePath {
            components: vec![comp],
        })
    }

    /// The path components.
    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// Join onto `root`, producing the on-disk path. The result is always
    /// inside `root` (verified by construction; also re-checked here).
    pub fn to_path(&self, root: &Path) -> PathBuf {
        let mut p = root.to_path_buf();
        for c in &self.components {
            p.push(c);
        }
        p
    }

    /// This path with `prefix` pushed in front (the torrent's top dir).
    pub fn prefixed(&self, prefix: &str) -> SafePath {
        let mut components = Vec::with_capacity(self.components.len() + 1);
        components.push(prefix.to_string());
        components.extend(self.components.iter().cloned());
        SafePath { components }
    }

    /// Display form using `/` separators (never used to open files).
    pub fn display(&self) -> String {
        self.components.join("/")
    }
}

/// Validate and normalise one path component. Returns `None` for anything
/// dangerous. Rejects: empty, `.`, `..`, NUL, `/` or `\\`, control chars,
/// trailing dot/space (Windows-hostile, and defensive), Windows-reserved
/// device names, and over-long components. Verifies via `Path::components`
/// that the result is a single `Normal` component.
fn sanitise_component(raw: &[u8]) -> Option<String> {
    if raw.is_empty() || raw.len() > MAX_COMPONENT {
        return None;
    }
    let s = std::str::from_utf8(raw).ok()?;
    if s == "." || s == ".." {
        return None;
    }
    if s.bytes()
        .any(|b| b == 0 || b == b'/' || b == b'\\' || b < 0x20)
    {
        return None;
    }
    // No path traversal or absolute markers survive.
    let mut it = Path::new(s).components();
    match (it.next(), it.next()) {
        (Some(Component::Normal(c)), None) if c.to_str() == Some(s) => {}
        _ => return None,
    }
    // Windows-hostile trailing dot/space.
    if s.ends_with('.') || s.ends_with(' ') {
        return None;
    }
    // Reserved Windows device names (case-insensitive, with or without ext).
    let stem = s.split('.').next().unwrap_or(s).to_ascii_uppercase();
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if RESERVED.contains(&stem.as_str()) {
        return None;
    }
    Some(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comp(s: &[u8]) -> Option<String> {
        sanitise_component(s)
    }

    #[test]
    fn rejects_traversal_and_absolutes() {
        assert!(comp(b"..").is_none());
        assert!(comp(b".").is_none());
        assert!(comp(b"/etc").is_none());
        assert!(comp(b"a/b").is_none());
        assert!(comp(b"a\\b").is_none());
        assert!(comp(b"a\0b").is_none());
        assert!(comp(b"").is_none());
        assert!(comp(b"con").is_none());
        assert!(comp(b"NUL.txt").is_none());
        assert!(comp(b"name.").is_none());
        assert!(comp(b"name ").is_none());
    }

    #[test]
    fn accepts_normal() {
        assert_eq!(comp(b"file.txt").as_deref(), Some("file.txt"));
        assert_eq!(comp("файл".as_bytes()).as_deref(), Some("файл"));
        assert_eq!(comp(b"..hidden").as_deref(), Some("..hidden"));
    }

    #[test]
    fn path_stays_within_root() {
        let p = SafePath::from_components(&[b"a", b"b", b"c.bin"], 0).unwrap();
        let joined = p.to_path(Path::new("/downloads"));
        assert_eq!(joined, Path::new("/downloads/a/b/c.bin"));
        assert!(joined.starts_with("/downloads"));
    }

    #[test]
    fn traversal_component_in_list_rejected() {
        assert!(SafePath::from_components(&[b"a", b"..", b"b"], 3).is_err());
        assert!(SafePath::from_components(&[], 0).is_err());
    }
}
