use curv::BigInt;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{Point, Secp256k1, Scalar};
use paillier::EncryptionKey;
use serde::{
    Serialize,
    Deserialize,
};
use sha2::Sha256;
use zk_paillier::zkproofs::{DLogStatement, NiCorrectKeyProof, CompositeDLogProof};


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenDecommitMessage {
    pub blind_factor: BigInt,
    pub y_i: Point<Secp256k1>,
}

// ing
// Decommitment of partial public EC schema key
// #[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
// pub struct DecommitPublicKey {
//     pub blind_factor: BigInt,
//     pub y_i: GE,
// }

// pub type GE = Secp256k1Point;

// #[derive(Clone, Debug, Copy)]
// pub struct Secp256k1Point {
//     purpose: &'static str,
//     ge: PK,
// }

// pub type SK = SecretKey;
// pub type PK = PublicKey;