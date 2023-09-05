use std::collections::BTreeSet;

use round_based::containers::push::Push;
use round_based::containers::{self, BroadcastMsgs, Store};
use round_based::Msg;

use crate::protocols::gg_2020::state_machine::keygen::messages::address::Address;
use crate::protocols::gg_2020::state_machine::keygen::{
    messages::{
        broadcast::KeyGenBroadcast,
        decommit::KeyGenDecommit,
        feldman_vss::FeldmanVSS,
        parameters::Parameters,
    },
    types::ProceedResult, 
    rounds::round_3::Round3, 
    error::proceed_error::ProceedError,
    party_i::keys::Keys,    
};



pub struct Round2 {
    pub(super) keys: Keys,
    pub(super) commitments: Vec<KeyGenBroadcast>,
    pub(super) decom: KeyGenDecommit,

    pub(super) own_party_index: u16,
    pub(super) other_parties: BTreeSet<u16>,
    pub(super) key_params: Parameters,
}

impl Round2 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<KeyGenDecommit>,
        mut output: O,
    ) -> ProceedResult<Round3>
    where
        O: Push<Msg<FeldmanVSS>>,
    {
        
        let received_decom = input.into_vec_including_me(self.decom);

        let vss_result = self
            .keys
            .phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute(
                &self.key_params,
                &received_decom,
                &self.commitments,
            )
            .map_err(ProceedError::Round2VerifyCommitments)?;

        for (i, share) in vss_result.1.iter().enumerate() {
            if i + 1 == usize::from(self.own_party_index) {
                continue;
            }

            output.push(Msg {
                sender: self.own_party_index,
                receiver: Some(i as u16 + 1),
                body: FeldmanVSS { 
                    vss: vss_result.0.clone(), 
                    share: share.clone(),
                    sender: self.own_party_index,
                    recipient: Address::Peer(i as u16 + 1),
                },
            })
        }

        Ok(Round3 {
            keys: self.keys,

            y_vec: received_decom.into_iter().map(|d| d.y_i).collect(),
            bc_vec: self.commitments,

            own_vss: vss_result.0.clone(),
            own_share: vss_result.1[usize::from(self.own_party_index - 1)].clone(),

            own_party_index: self.own_party_index,
            other_parties: self.other_parties.clone(),
            key_params: self.key_params,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<KeyGenDecommit>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}
