#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permissions {
    ReadOnly,
    ReadWrite,
    Administrator,
}

impl Permissions {
    pub fn is_authorized_to_read(&self) -> bool {
        match self {
            _ => true,
        }
    }

    pub fn is_authorized_to_write(&self) -> bool {
        match self {
            Permissions::ReadOnly => false,
            Permissions::ReadWrite | Permissions::Administrator => true,
        }
    }

    pub fn is_authorized_to_administer(&self) -> bool {
        match self {
            Permissions::Administrator => true,
            _ => false,
        }
    }
}
