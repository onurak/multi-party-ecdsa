pub mod parameters;
pub mod broadcast_message;
pub mod decommit_message;
pub mod feldman_vss;

use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::Secp256k1;
use serde::{
    Serialize,
    Deserialize,
};
use sha2::Sha256;

use self::broadcast_message::KeyGenBroadcastMessage;
use self::decommit_message::KeyGenDecommitMessage;
use self::feldman_vss::FeldmanVSS;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMessage(pub M);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum M {
    Round1(KeyGenBroadcastMessage),
    Round2(KeyGenDecommitMessage),
    Round3(FeldmanVSS),
    Round4(DLogProof<Secp256k1, Sha256>),
}





#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum Address {
    Peer(u16),
    Broadcast,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InputMessage<BodyType> {
    pub sender: u16,
    pub body: BodyType,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OutputMessage<BodyType> {
    pub recipient: Address,
    pub body: BodyType,
}


// ing
// /// Enumerates messages used by key generation algorithm
// #[derive(Debug, Clone, Deserialize, Serialize, Display)]
// pub enum Message {
//     R1(Phase1Broadcast),
//     R2(DecommitPublicKey),
//     R3(FeldmanVSS),
//     R4(DLogProof),
// }