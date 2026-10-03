use std::path::PathBuf;

use crate::client_side::error::ClientError;

/// Defines the host-key verification policy for an SSH connection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyPolicy {
    // Reject all server host keys by default
    RejectAll,

    // Verify the server host key against an OpenSSh known_hosts at a specific path
    KnownHost {
        path: PathBuf,
    },

    // Verify the server host key against an explicitly public key provided by client
    PinnedKey,

    // Verify the server host key against an explicitly fingerprint provided by client
    PinnedFingerprint,

    // Test-only policy that accepts any server host key
    #[cfg(any(test, feature = "test-utils"))]
    AcceptAnyForTesting,
}

pub fn verify_server_key() -> Result<bool, ClientError> {
    Ok(false)
}
