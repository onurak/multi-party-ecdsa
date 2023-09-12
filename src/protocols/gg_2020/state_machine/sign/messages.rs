
use curv::{
    elliptic::curves::{
        Scalar, 
        Secp256k1, 
        Point
    }, 
    cryptographic_primitives::proofs::{
        sigma_valid_pedersen::PedersenProof, 
        sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof
    }
};
use round_based::containers::push::Push;
use round_based::Msg;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{
    protocols::gg_2020::party_i::{
        SignBroadcastPhase1, 
        SignDecommitPhase1, 
    },
    utilities::{
        mta::MessageA,
        mta::MessageB,
        zk_pdl_with_slack::PDLwSlackProof,
    }
};



#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OfflineProtocolMessage(pub OfflineM);

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum OfflineM {
    M1((MessageA, SignBroadcastPhase1)),
    M2((GammaI, WI)),
    M3((DeltaI, TI, TIProof)),
    M4(SignDecommitPhase1),
    M5((RDash, Vec<PDLwSlackProof>)),
    M6((SI, HEGProof)),
}

pub struct MsgQueue(pub Vec<Msg<OfflineProtocolMessage>>);

macro_rules! make_pushable {
    ($($constructor:ident $t:ty),*$(,)?) => {
        $(
        impl Push<Msg<$t>> for MsgQueue {
            fn push(&mut self, m: Msg<$t>) {
                Vec::push(&mut self.0, Msg{
                    sender: m.sender,
                    receiver: m.receiver,
                    body: OfflineProtocolMessage(OfflineM::$constructor(m.body))
                })
            }
        }
        )*
    };
}

make_pushable! {
    M1 (MessageA, SignBroadcastPhase1),
    M2 (GammaI, WI),
    M3 (DeltaI, TI, TIProof),
    M4 SignDecommitPhase1,
    M5 (RDash, Vec<PDLwSlackProof>),
    M6 (SI, HEGProof),
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GammaI(pub MessageB);


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WI(pub MessageB);


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeltaI(pub Scalar<Secp256k1>);


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TI(pub Point<Secp256k1>);


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TIProof(pub PedersenProof<Secp256k1, Sha256>);


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RDash(pub Point<Secp256k1>);


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SI(pub Point<Secp256k1>);


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HEGProof(pub HomoELGamalProof<Secp256k1, Sha256>);
