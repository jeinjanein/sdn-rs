use std::net::SocketAddr;

use russh::client::Handle;

use crate::client_side::handler::ConnectionHandler;

pub struct SshClient {
    handle: Handle<ConnectionHandler>,
    connection_id: u64,
    remote_endpoint: Option<SocketAddr>,
}

impl SshClient {
    pub(crate) fn from_handle(
        handle: Handle<ConnectionHandler>,
        connection_id: u64,
        remote_endpoint: Option<SocketAddr>,
    ) -> Self {
        Self {
            handle,
            connection_id,
            remote_endpoint,
        }
    }

    pub(crate) fn handle_mut(&mut self) -> &mut Handle<ConnectionHandler> {
        &mut self.handle
    }

    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    pub fn connection_id(&self) -> u64 {
        self.connection_id
    }

    pub fn remote_endpoint(&self) -> Option<SocketAddr> {
        self.remote_endpoint
    }
}
