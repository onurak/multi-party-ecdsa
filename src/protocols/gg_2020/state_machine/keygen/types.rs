use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar, Curve};

use crate::protocols::gg_2020::state_machine::keygen::error::keygen_round_error::KeygenRoundError;

use super::error::keygen_error::KeygenError;

pub type ProceedResult<T> = std::result::Result<T, KeygenRoundError>;
pub type KeygenResult<T> = std::result::Result<T, KeygenError>;

pub type GE = Point<Secp256k1>;
pub type FE = Scalar<Secp256k1>;

pub type SecretShare<E: Curve> = (usize, Scalar<E>);