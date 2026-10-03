use crate::client_side::{known_hosts::HostKeyPolicy, target::TargetIdentity};

/// Represents the context of an SSH connection
#[derive(Debug, Clone)]
pub struct ConnectionContext {
    connection_id: u64,
    target_host: TargetIdentity,
    known_host_policy: HostKeyPolicy,
}
