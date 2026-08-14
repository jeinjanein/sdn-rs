use crate::client_side::error::ClientError;

#[derive(Debug, Default)]
pub struct ConnectionHandler;

impl russh::client::Handler for ConnectionHandler {
    type Error = ClientError;
}
