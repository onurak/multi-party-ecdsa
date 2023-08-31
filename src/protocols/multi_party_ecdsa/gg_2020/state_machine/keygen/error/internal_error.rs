use round_based::containers::StoreErr;

#[derive(Debug)]
#[non_exhaustive]
pub enum InternalError {
    /// [Messages store](super::MessageStore) reported that it received all messages it wanted to receive,
    /// but refused to return message container
    RetrieveRoundMessages(StoreErr),
    #[doc(hidden)]
    StoreGone,
}