use sha2::Sha256;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::Secp256k1;
use serde::{
    Serialize,
    Deserialize,
};

use super::address::Address;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub proof: DLogProof<Secp256k1, Sha256>,
    
    pub sender: u16,
    pub recipient: Address,
}

