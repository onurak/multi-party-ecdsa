use crate::protocols::gg_2020::state_machine::sign::{
    error::sign_round_error::SignRoundError,
    error::sign_error::SignError,
};

pub type SignResult<T, E = SignError> = std::result::Result<T, E>;
pub type SignRoundResult<T, E = SignRoundError> = std::result::Result<T, E>;