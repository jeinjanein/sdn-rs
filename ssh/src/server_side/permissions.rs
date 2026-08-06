#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permissions {
    ReadOnly,
    ReadWrite,
    Administrative,
}
