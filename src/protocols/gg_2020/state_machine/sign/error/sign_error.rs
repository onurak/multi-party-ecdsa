
use round_based::{containers::StoreErr, IsCritical};
use thiserror::Error;

use crate::protocols::gg_2020::state_machine::sign::{
    rounds,
    error::sign_round_error::SignRoundError,
    error::internal_error::InternalError,
};

#[derive(Debug, Error)]
pub enum SignError {
    /// Too few parties (`n < 2`)
    #[error("at least 2 parties are required for signing")]
    TooFewParties,
    /// Too many parties. `n` must fit into `u16`, so only `n < u16::MAX` values are supported.
    #[error("too many parties: n={n}, n must be less than 2^16")]
    TooManyParties { n: usize },
    /// Party index `i` is not in range `[1; n]`
    #[error("party index is not in range [1; n]")]
    InvalidPartyIndex,
    /// List `s_l` is invalid. Either it contains duplicates (`exist i j. i != j && s_l[i] = s_l[j]`),
    /// or contains index that is not in the range `[1; keygen_n]`, `keygen_n` — number of parties
    /// participated in DKG (`exist i. s_l[i] = 0 || s_l[i] > keygen_n`).
    #[error("invalid s_l")]
    InvalidSl,

    /// Round proceeding resulted in protocol error
    #[error("proceeding round: {0}")]
    ProceedRound(SignRoundError),

    /// Received message which we didn't expect to receive now (e.g. message from previous round)
    #[error(
        "didn't expect to receive message from round {msg_round} (being at round {current_round})"
    )]
    ReceivedOutOfOrderMessage { current_round: u16, msg_round: u16 },
    /// Received message didn't pass pre-validation
    #[error("received message didn't pass pre-validation: {0}")]
    HandleMessage(#[source] StoreErr),

    /// [OfflineStage::pick_output] called twice
    #[error("pick_output called twice")]
    DoublePickOutput,

    /// A bug in protocol implementation
    #[error("offline stage protocol bug: {0}")]
    Bug(InternalError),
}



impl From<InternalError> for SignError {
    fn from(err: InternalError) -> Self {
        SignError::Bug(err)
    }
}

impl IsCritical for SignError {
    fn is_critical(&self) -> bool {
        match self {
            SignError::TooFewParties => true,
            SignError::TooManyParties { .. } => true,
            SignError::InvalidPartyIndex => true,
            SignError::InvalidSl => true,
            SignError::ProceedRound(_) => true,
            SignError::ReceivedOutOfOrderMessage { .. } => false,
            SignError::HandleMessage(_) => false,
            SignError::DoublePickOutput => true,
            SignError::Bug(_) => true,
        }
    }
}