// File event types shared across monitoring modes.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileEventType {
    Create,
    Modify,
    Delete,
    Rename,
    PermissionChange,
    OwnerChange,
    Access,
    MetadataChange,
}

impl fmt::Display for FileEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create => write!(f, "CREATE"),
            Self::Modify => write!(f, "MODIFY"),
            Self::Delete => write!(f, "DELETE"),
            Self::Rename => write!(f, "RENAME"),
            Self::PermissionChange => write!(f, "PERMISSION"),
            Self::OwnerChange => write!(f, "OWNER"),
            Self::Access => write!(f, "ACCESS"),
            Self::MetadataChange => write!(f, "METADATA"),
        }
    }
}

impl FileEventType {
    pub fn icon(&self) -> &'static str {
        match self {
            Self::Create => "📝",
            Self::Delete => "🗑️",
            Self::Modify => "✏️",
            Self::Rename => "📋",
            Self::PermissionChange => "🔒",
            Self::OwnerChange => "👤",
            Self::Access => "👁️",
            Self::MetadataChange => "📎",
        }
    }

    pub fn is_security_relevant(&self) -> bool {
        matches!(self, Self::Delete | Self::Modify | Self::PermissionChange | Self::OwnerChange)
    }
}
