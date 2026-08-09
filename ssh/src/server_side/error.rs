use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
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

    #[error("Argon2 hash error: {source}")]
    PasswordHash {
        #[from]
        source: argon2::password_hash::Error,
    },

    #[error(
        "incomplete message is {message_size} bytes long, but no more than {maximum_size} bytes may be accepted"
    )]
    IncompleteMessageTooLarge {
        message_size: usize,
        maximum_size: usize,
    },

    #[error(
        "received message is {message_size} bytes long, but no more than {maximum_size} bytes may be accepted"
    )]
    MessageTooLarge {
        message_size: usize,
        maximum_size: usize,
    },
}
