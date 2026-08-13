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
    use russh::keys::PublicKey;

    use crate::server_side::{
        auth::{admin_password_authentication, check_admin_public_key, verify_password_hash},
        error::ServerError,
    };

    const DUMMY_ADMIN_PUBLIC_KEY: &str = concat!(
        "ssh-ed25519 ",
        "AAAAC3NzaC1lZDI1NTE5AAAAIJwutwmIIUraD6U+R31Ah6CBPiZijfoghZvET0dxOCT0 ",
        "dummy admin host key"
    );

    const UNAUTHORIZED_USER_KEY: &str = concat!(
        "ssh-ed25519 ",
        "AAAAC3NzaC1lZDI1NTE5AAAAIMlq7t9N7HBDMjRViAr6Z2CWUq91l1WUI+i644RC5Wi5 ",
        "random key to test"
    );

    fn parse_public_key(public_key: &str) -> PublicKey {
        PublicKey::from_openssh(public_key).expect("test public key should be valid")
    }

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

    #[test]
    fn malformed_password_has_returns_password_hash_error() {
        let result = verify_password_hash("admin", "not-argon2-hash");

        assert!(matches!(result, Err(ServerError::PasswordHash { .. })));
    }

    #[test]
    fn different_public_key_is_rejected() {
        let dummy_admin_key = parse_public_key(DUMMY_ADMIN_PUBLIC_KEY);

        let other_key = parse_public_key(UNAUTHORIZED_USER_KEY);

        assert!(!check_admin_public_key(&[dummy_admin_key], &other_key));
    }
}
