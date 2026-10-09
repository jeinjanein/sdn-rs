use std::net::SocketAddr;

/// Represents the network identity of an SSH server target
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetIdentity {
    hostname: String,
    port: u16,
    peer_addr: Option<SocketAddr>,
}

impl TargetIdentity {
    pub fn new(hostname: String, port: u16, peer_addr: Option<SocketAddr>) -> Self {
        Self {
            hostname,
            port,
            peer_addr,
        }
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn peer_addr(&self) -> &Option<SocketAddr> {
        &self.peer_addr
    }
}
