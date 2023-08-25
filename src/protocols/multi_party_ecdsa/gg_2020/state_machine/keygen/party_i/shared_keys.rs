use std::fmt::Debug;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedKeys {
    pub y: Point<Secp256k1>,
    pub x_i: Scalar<Secp256k1>,
}
