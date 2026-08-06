use russh::keys::PublicKey;

#[derive(Debug)]
pub struct ServerResources {
    authorized_public_keys: Vec<PublicKey>,
}

impl ServerResources {
    pub fn new(authorized_public_keys: Vec<PublicKey>) -> Self {
        Self {
            authorized_public_keys,
        }
    }

    pub fn authorized_public_keys(&self) -> &[PublicKey] {
        &self.authorized_public_keys
    }
}
