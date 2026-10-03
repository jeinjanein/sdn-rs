use std::net::SocketAddr;

/// Represents the network identity of an SSH server target
#[derive(Debug, Clone)]
pub struct TargetIdentity {
    hostname: String,
    port: u16,
    peer_addr: Option<SocketAddr>,
}
