use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Curve, Point};
use serde::{Deserialize, Serialize};
use paillier::EncryptionKey;
use zk_paillier::zkproofs::DLogStatement;

use super::party_i::shared_keys::SharedKeys;


/// Local secret obtained by party after [keygen](super::Keygen) protocol is completed
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LocalKey<E: Curve> {
    pub paillier_dk: paillier::DecryptionKey,
    pub pk_vec: Vec<Point<E>>,
    pub keys_linear: SharedKeys,
    pub paillier_key_vec: Vec<EncryptionKey>,
    pub y_sum_s: Point<E>,
    pub h1_h2_n_tilde_vec: Vec<DLogStatement>,
    pub vss_scheme: VerifiableSS<E>,
    pub i: u16,
    pub t: u16,
    pub n: u16,
}

impl LocalKey<Secp256k1> {
    /// Public key of secret shared between parties
    pub fn public_key(&self) -> Point<Secp256k1> {
        self.y_sum_s.clone()
    }
}
