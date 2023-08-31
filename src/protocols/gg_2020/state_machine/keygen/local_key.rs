use std::collections::BTreeSet;

use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Curve, Point};
use serde::{Deserialize, Serialize};
use paillier::EncryptionKey;
use zk_paillier::zkproofs::DLogStatement;

use crate::protocols::gg_2020::state_machine::keygen::messages::parameters::Parameters;

use super::party_i::shared_keys::SharedKeys;


/// Local secret obtained by party after [keygen](super::Keygen) protocol is completed
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LocalKey<E: Curve> {
    pub paillier_dk: paillier::DecryptionKey,
    pub pk_vec: Vec<Point<E>>,
    pub keys_linear: SharedKeys,
    pub paillier_key_vec: Vec<EncryptionKey>,
    pub h1_h2_n_tilde_vec: Vec<DLogStatement>,
    pub vss_scheme: VerifiableSS<E>,

    pub own_party_index: u16,
    pub other_parties: BTreeSet<u16>,
    pub public_key: Point<E>,
    pub key_params: Parameters,
}



// #[derive(Clone, Serialize, Deserialize, Debug)]
// pub struct MultiPartyInfo {
//     pub key_params: Parameters,                                          +++++           +++++
//     pub own_party_index: PartyIndex,                                                     +++++
//     pub secret_share: SecretShare,                                       +++++           +++++
//     pub public_key: GE,                                                  +++++           +++++
//     pub own_he_keys: PaillierKeys,                                                       +++++
//     pub party_he_keys: HashMap<PartyIndex, EncryptionKey>,                               +++++
//     pub party_to_point_map: Party2PointMap,                              +++++           +++++
//     pub range_proof_setups: Option<RangeProofSetups>,                                    +++++
// }


// impl MultiPartyInfo {
//     pub fn own_point(&self) -> usize {               +++
//         self.secret_share.0
//     }
//     pub fn own_share(&self) -> FE {                  ++++
//         self.secret_share.1
//     }
// }

// pub struct Parameters {
//     threshold: usize,   //t
//     share_count: usize, //n
// }

// pub type SecretShare = (usize, FE);


// pub type GE = Secp256k1Point;
// pub type FE = Secp256k1Scalar;
// pub type SK = SecretKey;
// pub type PK = PublicKey;
// pub struct SecretKey([u8; constants::SECRET_KEY_SIZE]);
// pub struct PublicKey(ffi::PublicKey);


// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct Party2PointMap {
//     pub points: HashMap<PartyIndex, usize>,
// }

// impl Party2PointMap {
//     #[trace(pretty)]
//     pub fn map_signing_parties_to_points(&self, signing_parties: &[PartyIndex]) -> Vec<usize> {
//         let mut present = Vec::new();
//         let mut absent = Vec::new();
//         for idx in signing_parties {
//             match self.points.get(idx) {
//                 Some(point) => present.push(*point),
//                 None => absent.push(*idx),
//             }
//         }

//         log::debug!(
//             "Panic is expected if not all parties are mapped to points.\nAbsent: {:?}",
//             absent
//         );
//         assert_eq!(absent.len(), 0);

//         present
//     }

//     #[trace(pretty)]
//     pub fn calculate_lagrange_multiplier(&self, signing_parties: &[PartyIndex], own_x: FE) -> FE {
//         // build set of points {1,2...}
//         #[allow(clippy::cast_possible_truncation)]
//         let subset_of_fe_points = self
//             .map_signing_parties_to_points(signing_parties)
//             .into_iter()
//             .map(|x| {
//                 let index_bn = BigInt::from(x as u32);
//                 ECScalar::from(&index_bn)
//             })
//             .collect::<Vec<FE>>();

//         let fold_with_one = |op: &dyn Fn(FE, &FE) -> FE| {
//             subset_of_fe_points
//                 .iter()
//                 .filter(|x| (*x).get_element() != own_x.get_element())
//                 .fold(ECScalar::from(&BigInt::one()), |acc: FE, x| op(acc, x))
//         };

//         let num_fun = |acc: FE, x: &FE| acc * x;
//         let denom_fun = |acc: FE, x: &FE| acc * x.sub(&own_x.get_element());

//         fold_with_one(&denom_fun).invert() * fold_with_one(&num_fun)
//     }
// }