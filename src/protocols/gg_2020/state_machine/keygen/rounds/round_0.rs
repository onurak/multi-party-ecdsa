
use std::collections::BTreeSet;

use round_based::containers::push::Push;
use round_based::Msg;

use crate::protocols::gg_2020::state_machine::keygen::{
    messages::{broadcast_message::KeyGenBroadcastMessage, parameters::Parameters},
    rounds::round_1::Round1,
    types::ProceedResult, 
    party_i::keys::Keys,
}; 

pub struct Round0 {
    pub own_party_index: u16,
    pub other_parties: BTreeSet<u16>,
    pub key_params: Parameters,
}

impl Round0 {
    pub fn proceed<O>(self, mut output: O) -> ProceedResult<Round1>
    where
        O: Push<Msg<KeyGenBroadcastMessage>>,
    {
        let party_keys = Keys::create_safe_prime(self.own_party_index as usize);
        let (bc1, decom1) =
            party_keys.phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2();

        output.push(Msg {
            sender: self.own_party_index,
            receiver: None,
            body: bc1.clone(),
        });
        Ok(Round1 {
            keys: party_keys,
            bc1,
            decom1,
            own_party_index: self.own_party_index,
            other_parties: self.other_parties.clone(),
            key_params: self.key_params,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
}

