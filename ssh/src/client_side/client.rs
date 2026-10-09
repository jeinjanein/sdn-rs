use crate::client_side::context::ConnectionContext;
use crate::client_side::handler::ConnectionHandler;
use russh::client::Handle;
use std::sync::Arc;

/// A wrapper around an established SSH connection
pub struct SshClient {
    handle: Handle<ConnectionHandler>,
    connection_context: Arc<ConnectionContext>,
}

impl SshClient {
    pub fn from_handle(
        handle: Handle<ConnectionHandler>,
        connection_context: Arc<ConnectionContext>,
    ) -> Self {
        Self {
            handle,
            connection_context,
        }
    }

    pub fn handle_mut(&mut self) -> &mut Handle<ConnectionHandler> {
        &mut self.handle
    }

    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    pub fn connection_context(&self) -> &ConnectionContext {
        &self.connection_context
    }
}
