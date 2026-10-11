use std::net::SocketAddr;

/// Represents the network identity of an SSH server target
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetIdentity {
    host_name: String,
    port: u16,
    peer_addr: Option<SocketAddr>,
}

impl TargetIdentity {
    pub fn new(host_name: String, port: u16, peer_addr: Option<SocketAddr>) -> Self {
        Self {
            host_name,
            port,
            peer_addr,
        }
    }

    pub fn host_name(&self) -> &str {
        &self.host_name
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn peer_addr(&self) -> &Option<SocketAddr> {
        &self.peer_addr
    }
}
