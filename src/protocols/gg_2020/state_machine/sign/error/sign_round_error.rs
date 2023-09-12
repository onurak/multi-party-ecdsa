use crate::protocols::gg_2020::ErrorType;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignRoundError {
    #[error("round 1: {0:?}")]
    Round1(ErrorType),
    #[error("round 2 stage 3: {0:?}")]
    Round2Stage3(crate::Error),
    #[error("round 2 stage 4: {0:?}")]
    Round2Stage4(ErrorType),
    #[error("round 3: {0:?}")]
    Round3(ErrorType),
    #[error("round 5: {0:?}")]
    Round5(ErrorType),
    #[error("round 6: verify proof: {0:?}")]
    Round6VerifyProof(ErrorType),
    #[error("round 6: check sig: {0:?}")]
    Round6CheckSig(crate::Error),
    #[error("round 7: {0:?}")]
    Round7(crate::Error),
}