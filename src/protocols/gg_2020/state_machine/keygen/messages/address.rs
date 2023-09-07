
use serde::{
    Serialize,
    Deserialize,
};


#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum Address {
    Peer(usize),
    Broadcast,
}
