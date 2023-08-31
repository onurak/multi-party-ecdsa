use round_based::containers::push::Push;
use round_based::containers::{self, BroadcastMsgs, Store};
use round_based::Msg;

use crate::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::{
    messages::{
        broadcast_message::KeyGenBroadcastMessage,
        decommit_message::KeyGenDecommitMessage,
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
    pub(super) received_comm: Vec<KeyGenBroadcastMessage>,
    pub(super) decom: KeyGenDecommitMessage,

    pub(super) party_i: u16,
    pub(super) t: u16,
    pub(super) n: u16,
}

impl Round2 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<KeyGenDecommitMessage>,
        mut output: O,
    ) -> ProceedResult<Round3>
    where
        O: Push<Msg<FeldmanVSS>>,
    {
        let params = Parameters {
            threshold: self.t,
            share_count: self.n,
        };
        let received_decom = input.into_vec_including_me(self.decom);

        let vss_result = self
            .keys
            .phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute(
                &params,
                &received_decom,
                &self.received_comm,
            )
            .map_err(ProceedError::Round2VerifyCommitments)?;

        for (i, share) in vss_result.1.iter().enumerate() {
            if i + 1 == usize::from(self.party_i) {
                continue;
            }

            output.push(Msg {
                sender: self.party_i,
                receiver: Some(i as u16 + 1),
                body: FeldmanVSS { vss: vss_result.0.clone(), share: share.clone()},
            })
        }

        Ok(Round3 {
            keys: self.keys,

            y_vec: received_decom.into_iter().map(|d| d.y_i).collect(),
            bc_vec: self.received_comm,

            own_vss: vss_result.0.clone(),
            own_share: vss_result.1[usize::from(self.party_i - 1)].clone(),

            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<KeyGenDecommitMessage>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}
