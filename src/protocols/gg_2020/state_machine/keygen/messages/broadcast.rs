use curv::BigInt;
use paillier::EncryptionKey;
use serde::{
    Serialize,
    Deserialize,
};
use zk_paillier::zkproofs::{
    DLogStatement, 
    NiCorrectKeyProof, 
    CompositeDLogProof
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenBroadcast {
    pub e: EncryptionKey,
    pub dlog_statement: DLogStatement,
    pub com: BigInt,
    pub correct_key_proof: NiCorrectKeyProof,
    pub composite_dlog_proof_base_h1: CompositeDLogProof,
    pub composite_dlog_proof_base_h2: CompositeDLogProof,
}


// ing
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct Phase1Broadcast {
//     pub e: EncryptionKey,
//     pub com: BigInt,
//     pub correct_key_proof: CorrectKeyProof,
//     pub range_proof_setup: Option<ZkpPublicSetup>,
// }