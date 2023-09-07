use std::collections::BTreeSet;

use round_based::containers::push::Push;
use round_based::containers::{self, BroadcastMsgs, Store};
use round_based::Msg;

use crate::protocols::gg_2020::state_machine::keygen::messages::parameters::Parameters;
use crate::protocols::gg_2020::state_machine::keygen::{
    messages::{
        broadcast::KeyGenBroadcast,
        decommit::KeyGenDecommit,
    },
    rounds::round_2::Round2,
    types::ProceedResult, 
    party_i::keys::Keys,
}; 

pub struct Round1 {
    pub(super) keys: Keys,
    pub(super) bc1: KeyGenBroadcast,
    pub(super) decom1: KeyGenDecommit,

    pub(super) own_party_index: usize,
    pub(super) other_parties: BTreeSet<usize>,
    pub(super) key_params: Parameters,
}

impl Round1 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<KeyGenBroadcast>,
        mut output: O,
    ) -> ProceedResult<Round2>
    where
        O: Push<Msg<KeyGenDecommit>>,
    {
        output.push(Msg {
            sender: self.own_party_index as u16,
            receiver: None,
            body: self.decom1.clone(),
        });
        Ok(Round2 {
            keys: self.keys,
            commitments: input.into_vec_including_me(self.bc1),
            decom: self.decom1,

            own_party_index: self.own_party_index,
            other_parties: self.other_parties.clone(),
            key_params: self.key_params,
        })
    }
    pub fn is_expensive(&self) -> bool {
        false
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<KeyGenBroadcast>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}
