use thiserror::Error;

use crate::protocols::gg_2020::ErrorType;


#[derive(Debug, Error)]
pub enum KeygenRoundError {
    #[error("round 2: verify commitments: {0:?}")]
    Round2VerifyCommitments(ErrorType),
    #[error("round 3: verify vss construction: {0:?}")]
    Round3VerifyVssConstruct(ErrorType),
    #[error("round 4: verify dlog proof: {0:?}")]
    Round4VerifyDLogProof(ErrorType),
}
