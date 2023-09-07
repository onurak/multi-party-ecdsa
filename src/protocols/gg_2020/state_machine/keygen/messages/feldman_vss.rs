use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{Secp256k1, Scalar};
use serde::{
    Serialize,
    Deserialize,
};

use crate::protocols::gg_2020::state_machine::keygen::types::SecretShare;

use super::address::Address;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeldmanVSS {
    pub vss: VerifiableSS<Secp256k1>, 
    pub share: SecretShare<Secp256k1>,
    
    pub sender: usize,
    pub recipient: Address,
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