use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};

/// Logical operations on a key-tree scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Permission {
    Read,
    Write,
    Insert,
    Update,
    Delete,
    /// Allows issuing narrower capabilities under this scope.
    Grant,
}

impl Permission {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
            Self::Insert => "INSERT",
            Self::Update => "UPDATE",
            Self::Delete => "DELETE",
            Self::Grant => "GRANT",
        }
    }

    pub fn all_variants() -> &'static [Permission] {
        &[
            Permission::Read,
            Permission::Write,
            Permission::Insert,
            Permission::Update,
            Permission::Delete,
            Permission::Grant,
        ]
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Permission {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "READ" => Ok(Self::Read),
            "WRITE" => Ok(Self::Write),
            "INSERT" => Ok(Self::Insert),
            "UPDATE" => Ok(Self::Update),
            "DELETE" => Ok(Self::Delete),
            "GRANT" => Ok(Self::Grant),
            _ => Err(Error::InvalidPath(format!("unknown permission: {s}"))),
        }
    }
}

/// Bit-set of permissions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PermissionSet(u8);

impl PermissionSet {
    const READ: u8 = 1 << 0;
    const WRITE: u8 = 1 << 1;
    const INSERT: u8 = 1 << 2;
    const UPDATE: u8 = 1 << 3;
    const DELETE: u8 = 1 << 4;
    const GRANT: u8 = 1 << 5;

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn all() -> Self {
        Self(Self::READ | Self::WRITE | Self::INSERT | Self::UPDATE | Self::DELETE | Self::GRANT)
    }

    pub const fn read_write() -> Self {
        Self(Self::READ | Self::WRITE | Self::INSERT | Self::UPDATE | Self::DELETE)
    }

    pub fn from_permissions(perms: &[Permission]) -> Self {
        let mut set = Self::empty();
        for p in perms {
            set = set.with(*p);
        }
        set
    }

    pub fn from_names(names: &[String]) -> Result<Self> {
        let mut set = Self::empty();
        for name in names {
            set = set.with(Permission::from_str(name)?);
        }
        Ok(set)
    }

    pub fn to_names(self) -> Vec<&'static str> {
        Permission::all_variants()
            .iter()
            .filter(|p| self.contains(**p))
            .map(|p| p.as_str())
            .collect()
    }

    pub const fn with(self, perm: Permission) -> Self {
        let bit = match perm {
            Permission::Read => Self::READ,
            Permission::Write => Self::WRITE,
            Permission::Insert => Self::INSERT,
            Permission::Update => Self::UPDATE,
            Permission::Delete => Self::DELETE,
            Permission::Grant => Self::GRANT,
        };
        Self(self.0 | bit)
    }

    pub const fn contains(self, perm: Permission) -> bool {
        let bit = match perm {
            Permission::Read => Self::READ,
            Permission::Write => Self::WRITE,
            Permission::Insert => Self::INSERT,
            Permission::Update => Self::UPDATE,
            Permission::Delete => Self::DELETE,
            Permission::Grant => Self::GRANT,
        };
        self.0 & bit != 0
    }

    pub const fn is_subset_of(self, other: Self) -> bool {
        self.0 & other.0 == self.0
    }

    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}
