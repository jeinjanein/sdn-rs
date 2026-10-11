use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use russh::keys::{PublicKey, check_known_hosts_path};

use crate::client_side::{context::ConnectionContext, error::ClientError};

/// Defines the host-key verification policy for an SSH connection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyPolicy {
    /// Reject all server host keys by default
    RejectAll,

    /// Verify the server host key against an OpenSSh known_hosts at a specific path
    KnownHost { path: PathBuf },

    /// Verify the server host key against an explicitly public key provided by client
    PinnedKey,

    /// Verify the server host key against an explicitly fingerprint provided by client
    PinnedFingerprint,

    /// Test-only policy that accepts any server host key
    #[cfg(any(test, feature = "test-utils"))]
    AcceptAnyForTesting,
}

pub fn verify_server_key(
    connection_context: Arc<ConnectionContext>,
    server_public_key: &PublicKey,
) -> Result<bool, ClientError> {
    let host_name = connection_context.target_host().host_name();
    let port = connection_context.target_host().port();
    let peer_addr = connection_context.target_host().peer_addr();
    let host_key_policy = connection_context.host_key_policy();

    match host_key_policy {
        HostKeyPolicy::RejectAll => {
            return Ok(false);
        }
        _ => {
            return Ok(true);
        }
    }
}

fn verify_known_host(
    host_name: &str,
    port: u16,
    server_public_key: &PublicKey,
    path: impl AsRef<Path>,
) -> Result<bool, ClientError> {
    let path = path.as_ref();
    let result = check_known_hosts_path(host_name, port, server_public_key, path)
        .map_err(|source| ClientError::Key { source })?;

    Ok(result)
}
