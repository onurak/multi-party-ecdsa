use round_based::{containers::StoreErr, IsCritical};
use thiserror::Error;

use crate::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::error::{
    proceed_error::ProceedError,
    internal_error::InternalError,
};




/// Error type of keygen protocol
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum KeygenError {
    /// Round proceeding resulted in error
    #[error("proceed round: {0}")]
    ProceedRound(#[source] ProceedError),

    /// Too few parties (`n < 2`)
    #[error("at least 2 parties are required for keygen")]
    TooFewParties,
    /// Threshold value `t` is not in range `[1; n-1]`
    #[error("threshold is not in range [1; n-1]")]
    InvalidThreshold,
    /// Party index `i` is not in range `[1; n]`
    #[error("party index is not in range [1; n]")]
    InvalidPartyIndex,

    /// Received message didn't pass pre-validation
    #[error("received message didn't pass pre-validation: {0}")]
    HandleMessage(#[source] StoreErr),
    /// Received message which we didn't expect to receive now (e.g. message from previous round)
    #[error(
        "didn't expect to receive message from round {msg_round} (being at round {current_round})"
    )]
    ReceivedOutOfOrderMessage { current_round: u16, msg_round: u16 },
    /// [Keygen::pick_output] called twice
    #[error("pick_output called twice")]
    DoublePickOutput,

    /// Some internal assertions were failed, which is a bug
    #[doc(hidden)]
    #[error("internal error: {0:?}")]
    InternalError(InternalError),
}

impl IsCritical for KeygenError {
    fn is_critical(&self) -> bool {
        true
    }
}

impl From<InternalError> for KeygenError {
    fn from(err: InternalError) -> Self {
        Self::InternalError(err)
    }
}
