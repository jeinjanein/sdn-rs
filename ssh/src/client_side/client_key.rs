use std::{fs::File, path::Path};

use russh::keys::PrivateKey;

use crate::client_side::error::ClientKeyError;

pub fn load_client_private_key(path: impl AsRef<Path>) -> Result<PrivateKey, ClientKeyError> {
    let mut file = File::open(path).map_err(|source| ClientKeyError::Open { source })?;

    let key =
        PrivateKey::read_openssh(&mut file).map_err(|source| ClientKeyError::Read { source })?;

    if key.is_encrypted() {
        return Err(ClientKeyError::Encrypted);
    }

    Ok(key)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use russh::keys::{PrivateKey, ssh_key::private::Ed25519Keypair};

    use crate::client_side::{client_key::load_client_private_key, error::ClientKeyError};

    const TEST_CLIENT_KEY_SEED: [u8; 32] = [9; 32];

    // Test key
    const ENCRYPTED_CLIENT_KEY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABChi+wIP7
rKWtG5UbhcDTbsAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJEYxaEw5aFaKU9F
i8e/lST6JtQfDbi31qEO5b6kgIl/AAAAoPKxbCv9KDESpbPkGnyvXGNH4v71gD3KnHFH8w
6DFm9Nto8aHl8QR/LHwmOLtKV/3xVIkdZ9I36vfyod9pidbZPHQy0KZAMB/smFBEloIeu+
glOVuriTXTClxAk9RTnVj+Q+hU4YzlF5Neg/pztE4cBnInkYBme/aIh8JnNSLuiiOvmjCG
hQ9CGekfboVnlAmPCAm+ASKyjHm9UaVgEHiKk=
-----END OPENSSH PRIVATE KEY-----
";

    fn test_key_path(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("ssh-client-key-test-{}-{name}", std::process::id()));

        let _ = fs::remove_file(&path);

        path
    }

    fn test_client_key() -> PrivateKey {
        PrivateKey::from(Ed25519Keypair::from_seed(&TEST_CLIENT_KEY_SEED))
    }

    #[test]
    fn loads_an_unencrypted_openssh_key() {
        let path = test_key_path("unencrypted");
        let expected = test_client_key();

        expected
            .write_openssh_file(&path, russh::keys::ssh_key::LineEnding::LF)
            .expect("test key should be written");

        let loaded = load_client_private_key(&path).expect("unencrypted key should load");

        fs::remove_file(&path).expect("test key file should be removed");
        assert!(!loaded.is_encrypted());
        assert_eq!(loaded.public_key(), expected.public_key());
    }

    #[test]
    fn refuses_an_encrypted_key() {
        let path = test_key_path("encrypted");
        fs::write(&path, ENCRYPTED_CLIENT_KEY).expect("test key should be written");

        let result = load_client_private_key(&path);

        fs::remove_file(&path).expect("test key file should be removed");
        assert!(matches!(result, Err(ClientKeyError::Encrypted)));
    }

    #[test]
    fn refuses_a_public_key_file() {
        let path = test_key_path("public");
        let public_key = test_client_key()
            .public_key()
            .to_openssh()
            .expect("test public key should encode");

        fs::write(&path, public_key).expect("test public key should be written");

        let result = load_client_private_key(&path);

        fs::remove_file(&path).expect("test key file should be removed");

        assert!(matches!(result, Err(ClientKeyError::Read { .. })));
    }
}
