use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use russh::keys::{PublicKey, check_known_hosts_path, ssh_key::Fingerprint};

use crate::client_side::{context::ConnectionContext, error::ClientError};

/// Defines the host-key verification policy for an SSH connection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyPolicy {
    /// Reject all server host keys by default
    RejectAll,

    /// Verify the server host key against an OpenSSh known_hosts at a specific path
    KnownHost { path: PathBuf },

    /// Verify the server host key against a public key provided by client
    PinnedKey { key: PublicKey },
    /// Verify the server host key against a fingerprint provided by client
    PinnedFingerprint { fingerprint: Fingerprint },

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
    let host_key_policy = connection_context.host_key_policy();

    match host_key_policy {
        HostKeyPolicy::RejectAll => {
            return Ok(false);
        }

        HostKeyPolicy::KnownHost { path } => {
            return verify_known_host(host_name, port, server_public_key, path);
        }

        HostKeyPolicy::PinnedKey { key } => {
            return verify_pinned_key(key, server_public_key);
        }

        HostKeyPolicy::PinnedFingerprint { fingerprint } => {
            return verify_pinned_fingerprint(fingerprint, server_public_key);
        }

        #[cfg(any(test, feature = "test-utils"))]
        HostKeyPolicy::AcceptAnyForTesting => {
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
    let result =
        check_known_hosts_path(host_name, port, server_public_key, path).map_err(|error| {
            match error {
                russh::keys::Error::KeyChanged { line } => ClientError::HostKeyChanged {
                    host: host_name.to_owned(),
                    port,
                    path: path.to_path_buf(),
                    line,
                },

                _ => ClientError::Key { source: error },
            }
        })?;

    Ok(result)
}

fn verify_pinned_key(
    pinned_keys: &PublicKey,
    server_public_key: &PublicKey,
) -> Result<bool, ClientError> {
    Ok(pinned_keys.key_data() == server_public_key.key_data())
}

fn verify_pinned_fingerprint(
    pinned_fingerprints: &Fingerprint,
    server_public_key: &PublicKey,
) -> Result<bool, ClientError> {
    Ok(*pinned_fingerprints == server_public_key.fingerprint(pinned_fingerprints.algorithm()))
}

#[cfg(test)]
mod tests {
    use russh::keys::PublicKey;

    use crate::client_side::{
        error::ClientError,
        known_hosts::{verify_known_host, verify_pinned_key},
    };

    const KNOWN_HOSTS_PATH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/known_hosts");

    #[test]
    fn verify_known_host_public_key_matches() {
        let host_name = "192.168.1.100";
        let port = 4949_u16;
        let server_public_key = PublicKey::from_openssh(concat!(
            "ssh-ed25519 ",
            "AAAAC3NzaC1lZDI1NTE5AAAAIC+fYzCAKlbWAvB5Ydts/mo5Q443cvyzjXdMws4hTHBo"
        ))
        .expect("should be able to create OpenSSH-formatted public key");

        let result = verify_known_host(host_name, port, &server_public_key, KNOWN_HOSTS_PATH)
            .expect("server public key should match");

        assert!(result);
    }

    #[test]
    fn verify_known_host_public_key_changed() {
        let host_name = "router.example1.com";
        let port = 2222_u16;
        let changed_server_public_key = PublicKey::from_openssh(concat!(
            "ssh-ed25519 ",
            "AAAAC3NzaC1lZDI1NTE5AAAAIC+fYzCAKlbWAvB5Ydts/mo5Q443cvyzjXdMws4hTHBo"
        ))
        .expect("should be able to create OpenSSH-formatted public key");

        let result = verify_known_host(
            host_name,
            port,
            &changed_server_public_key,
            KNOWN_HOSTS_PATH,
        )
        .expect_err("unmatch host key should return HostKeyChanged error");

        assert!(matches!(result, ClientError::HostKeyChanged { .. }));
    }

    #[test]
    fn verify_pinned_key_public_key_matches() {
        let pinned_key = PublicKey::from_openssh(concat!(
            "ssh-ed25519 ",
            "AAAAC3NzaC1lZDI1NTE5AAAAINU0dNEp2u7eCNMf1M3ZRejErz2QUqYh6EJs/+CFUrnf ",
            "pinned key"
        ))
        .expect("should be able to create OpenSSH-formatted public key");

        let server_public_key = PublicKey::from_openssh(concat!(
            "ssh-ed25519 ",
            "AAAAC3NzaC1lZDI1NTE5AAAAINU0dNEp2u7eCNMf1M3ZRejErz2QUqYh6EJs/+CFUrnf ",
            "server key"
        ))
        .expect("should be able to create OpenSSH-formatted public key");

        let result = verify_pinned_key(&pinned_key, &server_public_key)
            .expect("server public key should match one of the key in the list");

        assert!(result);
    }
}
