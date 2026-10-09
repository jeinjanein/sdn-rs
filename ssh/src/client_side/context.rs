use crate::client_side::{known_hosts::HostKeyPolicy, target::TargetIdentity};

/// Represents the context of an SSH connection
#[derive(Debug, Clone)]
pub struct ConnectionContext {
    connection_id: u64,
    target_host: TargetIdentity,
    known_host_policy: HostKeyPolicy,
}


impl ConnectionContext {
    pub fn new(connection_id: u64, target_host: TargetIdentity, known_host_policy: HostKeyPolicy) -> Self {
        Self { connection_id, target_host, known_host_policy }
    }

    pub fn connection_id(&self) -> u64 {
        self.connection_id
    }

    pub fn target_host(&self) -> &TargetIdentity {
        &self.target_host
    }

    pub fn known_host_policy(&self) -> &HostKeyPolicy {
        &self.known_host_policy
    }
}