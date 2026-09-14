use std::fmt;

use crate::error::{Error, Result};

/// Hierarchical path in the key tree, e.g. `company/finance/invoices`.
///
/// Segments are non-empty, `/`-separated, no leading/trailing slash.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyPath {
    raw: String,
}

impl KeyPath {
    pub const ROOT: Self = Self { raw: String::new() };

    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim().trim_matches('/');
        if trimmed.is_empty() {
            return Ok(Self::root());
        }
        for seg in trimmed.split('/') {
            if seg.is_empty() || seg == "." || seg == ".." {
                return Err(Error::InvalidPath(input.to_string()));
            }
            if seg.contains('\0') {
                return Err(Error::InvalidPath(input.to_string()));
            }
        }
        Ok(Self {
            raw: trimmed.to_string(),
        })
    }

    pub fn root() -> Self {
        Self { raw: String::new() }
    }

    pub fn is_root(&self) -> bool {
        self.raw.is_empty()
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// HKDF info label for this path.
    pub fn info_label(&self) -> String {
        if self.is_root() {
            "root".to_string()
        } else {
            format!("node/{}", self.raw)
        }
    }

    pub fn segments(&self) -> Vec<&str> {
        if self.is_root() {
            Vec::new()
        } else {
            self.raw.split('/').collect()
        }
    }

    pub fn parent(&self) -> Option<Self> {
        if self.is_root() {
            return None;
        }
        match self.raw.rfind('/') {
            Some(i) => Some(Self {
                raw: self.raw[..i].to_string(),
            }),
            None => Some(Self::root()),
        }
    }

    pub fn join(&self, segment: &str) -> Result<Self> {
        if segment.is_empty() || segment.contains('/') || segment == "." || segment == ".." {
            return Err(Error::InvalidPath(segment.to_string()));
        }
        if self.is_root() {
            Self::parse(segment)
        } else {
            Self::parse(&format!("{}/{}", self.raw, segment))
        }
    }

    /// True if `self` is an ancestor of `other` (or equal).
    pub fn is_prefix_of(&self, other: &Self) -> bool {
        if self.is_root() {
            return true;
        }
        if self == other {
            return true;
        }
        other.raw.starts_with(&self.raw) && other.raw.as_bytes().get(self.raw.len()) == Some(&b'/')
    }

    /// Relative segments from `ancestor` down to `self`.
    pub fn relative_to(&self, ancestor: &Self) -> Result<Vec<String>> {
        if !ancestor.is_prefix_of(self) {
            return Err(Error::InvalidPath(format!(
                "{} is not under {}",
                self.raw, ancestor.raw
            )));
        }
        if ancestor == self {
            return Ok(Vec::new());
        }
        let rest = if ancestor.is_root() {
            self.raw.as_str()
        } else {
            &self.raw[ancestor.raw.len() + 1..]
        };
        Ok(rest.split('/').map(str::to_string).collect())
    }
}

impl fmt::Display for KeyPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            f.write_str("/")
        } else {
            write!(f, "/{}", self.raw)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_and_relative() {
        let root = KeyPath::root();
        let finance = KeyPath::parse("company/finance").unwrap();
        let inv = KeyPath::parse("company/finance/invoices").unwrap();
        assert!(root.is_prefix_of(&finance));
        assert!(finance.is_prefix_of(&inv));
        assert!(!inv.is_prefix_of(&finance));
        assert_eq!(
            inv.relative_to(&finance).unwrap(),
            vec!["invoices".to_string()]
        );
    }
}
