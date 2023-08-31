use curv::elliptic::curves::{secp256_k1::Secp256k1, Curve, Point, Scalar};

use crate::protocols::gg_2020::state_machine::keygen::error::proceed_error::ProceedError;

use super::error::keygen_error::KeygenError;


pub type ProceedResult<T> = std::result::Result<T, ProceedError>;
pub type KeygenResult<T> = std::result::Result<T, KeygenError>;


// pub type SecretShare = (usize, FE);


pub type GE = Point<Secp256k1>;
pub type FE = Scalar<Secp256k1>;