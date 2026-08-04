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
    PasswordHaSH {
        #[from]
        source: argon2::password_hash::Error,
    },
}
