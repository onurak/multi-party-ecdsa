use thiserror::Error;

use crate::protocols::gg_2020::state_machine::sign::error::sign_round_error::SignRoundError;

#[derive(Debug, Error)]
pub enum SignLocalCompleteError {
    #[error("signing message locally: {0}")]
    LocalSigning(SignRoundError),
    #[error("couldn't complete signing: {0}")]
    CompleteSigning(SignRoundError),
}