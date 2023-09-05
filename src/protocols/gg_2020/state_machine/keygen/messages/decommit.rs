use curv::BigInt;
use curv::elliptic::curves::{Point, Secp256k1};
use serde::{
    Serialize,
    Deserialize,
};


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenDecommit {
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