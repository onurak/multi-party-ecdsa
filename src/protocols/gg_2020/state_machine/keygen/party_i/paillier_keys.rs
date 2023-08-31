use paillier::{DecryptionKey, EncryptionKey, };
use serde::{Serialize, Deserialize};

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct PaillierKeys {
    pub dk: DecryptionKey,
    pub ek: EncryptionKey,
}

impl PaillierKeys {

    pub fn new(dk:DecryptionKey, ek:EncryptionKey) -> Self {
        Self {
            dk,
            ek
        }
    }
}

