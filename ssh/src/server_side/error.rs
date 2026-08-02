use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("SSH error: {source}")]
    SshError {
        #[from]
        source: russh::Error,
    },

    #[error("SSH keys error: {source}")]
    KeyError {
        #[from]
        source: russh::keys::Error,
    },
}
