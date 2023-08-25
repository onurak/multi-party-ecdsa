pub mod round_0;
pub mod round_1;
pub mod round_2;
pub mod round_3;
pub mod round_4;


use thiserror::Error;
use crate::protocols::multi_party_ecdsa::gg_2020::ErrorType;

pub type Result<T> = std::result::Result<T, ProceedError>;

#[derive(Debug, Error)]
pub enum ProceedError {
    #[error("round 2: verify commitments: {0:?}")]
    Round2VerifyCommitments(ErrorType),
    #[error("round 3: verify vss construction: {0:?}")]
    Round3VerifyVssConstruct(ErrorType),
    #[error("round 4: verify dlog proof: {0:?}")]
    Round4VerifyDLogProof(ErrorType),
}
