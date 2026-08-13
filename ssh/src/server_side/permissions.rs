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

#[cfg(test)]
mod tests {
    use crate::server_side::permissions::Permissions;

    #[test]
    fn read_only_can_only_read_but_cannot_write_or_administer() {
        let permissions = Permissions::ReadOnly;

        assert!(permissions.is_authorized_to_read());

        assert!(!permissions.is_authorized_to_write());

        assert!(!permissions.is_authorized_to_administer());
    }

    #[test]
    fn read_write_can_read_and_write_but_cannot_administer() {
        let permissions = Permissions::ReadWrite;

        assert!(permissions.is_authorized_to_read());

        assert!(permissions.is_authorized_to_write());

        assert!(!permissions.is_authorized_to_administer());
    }

    #[test]
    fn administrator_can_read_write_and_administer() {
        let permissions = Permissions::Administrator;

        assert!(permissions.is_authorized_to_read());

        assert!(permissions.is_authorized_to_write());

        assert!(permissions.is_authorized_to_administer());
    }
}
