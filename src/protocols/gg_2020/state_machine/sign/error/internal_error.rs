use round_based::containers::StoreErr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InternalError {
    #[error("store gone")]
    StoreGone,
    #[error("store reported that it's collected all the messages it needed, but refused to give received messages")]
    RetrieveMessagesFromStore(StoreErr),
    #[error("decommit round expected to be in NotStarted state")]
    DecommitRoundWasntInInitialState,
}