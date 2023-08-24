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

pub type SecretShare = (usize, Scalar<Secp256k1>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeldmanVSS {
    pub vss: VerifiableSS<Secp256k1>, 
    pub share: SecretShare,
}

// zengo
//  (VerifiableSS<Secp256k1>, Scalar<Secp256k1>)


// ing
// #[derive(Debug, Clone, Deserialize, Serialize)]
// pub struct FeldmanVSS {
//     pub vss: VerifiableSS,
//     pub share: SecretShare,
// }

// Shamir's secret share
//
// Contains x and y-coordinate of the point
// pub type SecretShare = (usize, FE);
// pub type FE = Secp256k1Scalar;