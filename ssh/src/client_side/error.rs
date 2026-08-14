use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("SSH error: {source}")]
    Ssh {
        #[from]
        source: russh::Error,
    },
}
