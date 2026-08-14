use russh::client::Handle;

use crate::client_side::handler::ConnectionHandler;

pub struct SshClient {
    handle: Handle<ConnectionHandler>,
}

impl SshClient {
    pub(crate) fn from_handle(handle: Handle<ConnectionHandler>) -> Self {
        Self { handle }
    }

    pub(crate) fn handle_mut(&mut self) -> &mut Handle<ConnectionHandler> {
        &mut self.handle
    }

    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }
}
