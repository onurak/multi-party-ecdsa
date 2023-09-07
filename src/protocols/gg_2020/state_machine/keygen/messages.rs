pub mod parameters;
pub mod broadcast;
pub mod decommit;
pub mod feldman_vss;
pub mod proof;
pub mod address;

use serde::{
    Serialize,
    Deserialize,
};

use self::broadcast::KeyGenBroadcast;
use self::decommit::KeyGenDecommit;
use self::feldman_vss::FeldmanVSS;
use self::proof::Proof;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMessage(pub M);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum M {
    Round1(KeyGenBroadcast),
    Round2(KeyGenDecommit),
    Round3(FeldmanVSS),
    Round4(Proof),
}



// #[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
// pub enum Address {
//     Peer(u16),
//     Broadcast,
// }

// #[derive(Debug, Clone, Deserialize, Serialize)]
// pub struct InputMessage<BodyType> {
//     pub sender: u16,
//     pub recipient: Address,
//     pub body: BodyType,
// }

// #[derive(Debug, Clone, Deserialize, Serialize)]
// pub struct OutputMessage<BodyType> {
//     pub recipient: Address,
//     pub body: BodyType,
// }


// ing
// /// Enumerates messages used by key generation algorithm
// #[derive(Debug, Clone, Deserialize, Serialize, Display)]
// pub enum Message {
//     R1(Phase1Broadcast),
//     R2(DecommitPublicKey),
//     R3(FeldmanVSS),
//     R4(DLogProof),
// }