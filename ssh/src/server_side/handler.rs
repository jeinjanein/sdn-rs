use std::sync::atomic::AtomicU64;

use crate::server_side::error::ServerError;

#[derive(Debug)]
pub struct ConnectionHandler {
    connection_id: u64,
}

impl ConnectionHandler {
    pub fn new(connection_id: u64) -> Self {
        Self { connection_id }
    }
}

impl russh::server::Handler for ConnectionHandler {
    type Error = ServerError;
}
