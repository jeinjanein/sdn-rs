use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use russh::keys::PublicKey;

use crate::server_side::{
    error::ServerError,
    security::{DEVELOPMENT_PASSWORD_HASH, DEVELOPMENT_USERNAME},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationMethods {
    Password,
    PublicKey,
}

fn hash_password(password: &str) -> Result<String, ServerError> {
    let salt = SaltString::generate(&mut OsRng);

    let password_hash = Argon2::default().hash_password(password.as_bytes(), &salt)?;

    Ok(password_hash.to_string())
}

pub fn verify_password_hash(password: &str, password_hash: &str) -> Result<(), ServerError> {
    let parsed_hash = PasswordHash::new(password_hash)?;

    Ok(Argon2::default().verify_password(password.as_bytes(), &parsed_hash)?)
}

pub fn admin_password_authentication(username: &str, password: &str) -> bool {
    username == DEVELOPMENT_USERNAME
        && verify_password_hash(password, DEVELOPMENT_PASSWORD_HASH).is_ok()
}

pub fn check_admin_public_key(authorized_keys: &[PublicKey], key_to_check: &PublicKey) -> bool {
    authorized_keys
        .iter()
        .any(|key| key.key_data() == key_to_check.key_data())
}

#[cfg(test)]
mod tests {
    use crate::server_side::auth::admin_password_authentication;

    #[test]
    fn validate_admin() {
        let username = "admin";
        let password = "admin";

        assert!(admin_password_authentication(username, password));
    }

    #[test]
    fn reject_unknown_user() {
        let username = "unknown";
        let password = "password";

        assert!(!admin_password_authentication(username, password));
    }

    #[test]
    fn reject_admin_wrong_password() {
        let username = "admin";
        let password = "asdasdasd";
        assert!(!admin_password_authentication(username, password));
    }
}
