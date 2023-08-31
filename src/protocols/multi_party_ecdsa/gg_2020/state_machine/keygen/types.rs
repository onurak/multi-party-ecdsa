use crate::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::error::proceed_error::ProceedError;

use super::error::keygen_error::KeygenError;


pub type ProceedResult<T> = std::result::Result<T, ProceedError>;
pub type KeygenResult<T> = std::result::Result<T, KeygenError>;