use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
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
}
