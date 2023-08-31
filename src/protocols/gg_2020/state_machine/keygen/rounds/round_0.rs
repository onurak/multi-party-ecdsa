
use round_based::containers::push::Push;
use round_based::Msg;

use crate::protocols::gg_2020::state_machine::keygen::{
    messages::broadcast_message::KeyGenBroadcastMessage,
    rounds::round_1::Round1,
    types::ProceedResult, 
    party_i::keys::Keys,
}; 

pub struct Round0 {
    pub party_i: u16,
    pub t: u16,
    pub n: u16,
}

impl Round0 {
    pub fn proceed<O>(self, mut output: O) -> ProceedResult<Round1>
    where
        O: Push<Msg<KeyGenBroadcastMessage>>,
    {
        let party_keys = Keys::create_safe_prime(self.party_i as usize);
        let (bc1, decom1) =
            party_keys.phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2();

        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: bc1.clone(),
        });
        Ok(Round1 {
            keys: party_keys,
            bc1,
            decom1,
            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
}

