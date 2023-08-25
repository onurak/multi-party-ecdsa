use round_based::containers::push::Push;
use round_based::containers::{self, BroadcastMsgs, Store};
use round_based::Msg;

use crate::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::{
    messages::{
        broadcast_message::KeyGenBroadcastMessage,
        decommit_message::KeyGenDecommitMessage,
    },
    rounds::{
        Result, 
        round_2::Round2,
    },
    party_i::keys::Keys,
}; 

pub struct Round1 {
    pub(super) keys: Keys,
    pub(super) bc1: KeyGenBroadcastMessage,
    pub(super) decom1: KeyGenDecommitMessage,
    pub(super) party_i: u16,
    pub(super) t: u16,
    pub(super) n: u16,
}

impl Round1 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<KeyGenBroadcastMessage>,
        mut output: O,
    ) -> Result<Round2>
    where
        O: Push<Msg<KeyGenDecommitMessage>>,
    {
        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: self.decom1.clone(),
        });
        Ok(Round2 {
            keys: self.keys,
            received_comm: input.into_vec_including_me(self.bc1),
            decom: self.decom1,

            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        false
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<KeyGenBroadcastMessage>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}
