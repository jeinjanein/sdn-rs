use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("SSH host key changed for {host}:{port} at {path}:{line}")]
    HostKeyChanged {
        host: String,
        port: u16,
        path: PathBuf,
        line: usize,
    },

    #[error("SSH handshake failed: {source}")]
    SshHandshake {
        #[source]
        source: russh::Error,
    },

    #[error("SSH error: {source}")]
    Ssh {
        #[from]
        source: russh::Error,
    },

    #[error("SSH keys error: {source}")]
    Key {
        #[from]
        source: russh::keys::Error,
    },

    #[error("failed to resolve target host name {hostname}: {source}")]
    Dns {
        hostname: String,
        #[source]
        source: std::io::Error,
    },

    #[error("TCP connection refused: {source}")]
    TcpConnectionRefused {
        #[source]
        source: std::io::Error,
    },

    #[error("TCP host unreachable: {source}")]
    TcpHostUnreachable {
        #[source]
        source: std::io::Error,
    },

    #[error("TCP connection timed out: {source}")]
    TcpTimeout {
        #[source]
        source: std::io::Error,
    },

    #[error("TCP connection error: {source}")]
    TcpConnection {
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Error)]
pub enum ClientKeyError {
    #[error("cannot open private key file: {source}")]
    Open {
        #[source]
        source: std::io::Error,
    },

    #[error("cannot read OpenSSH private key: {source}")]
    Read {
        #[source]
        source: russh::keys::ssh_key::Error,
    },

    #[error("private key is encrypted, and passphrase are not supported yet")]
    Encrypted,
}
