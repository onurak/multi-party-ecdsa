use std::collections::{BTreeSet, HashMap};

use curv::elliptic::curves::{Secp256k1, Scalar};
use round_based::containers::push::Push;
use round_based::containers::{self, BroadcastMsgs, Store};
use round_based::Msg;

use crate::protocols::gg_2020::state_machine::keygen::messages::address::Address;
use crate::protocols::gg_2020::state_machine::keygen::types::{FE, SecretShare};
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

    pub(super) own_party_index: usize,
    pub(super) other_parties: BTreeSet<usize>,
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

        let mut mapped_shares: HashMap<usize, (usize, Scalar<Secp256k1>)> = HashMap::new();
        
        for (i, share) in vss_result.1.iter().enumerate() {

            mapped_shares.insert(i+1, (i + 1, share.clone()));

            if i + 1 == self.own_party_index {
                continue;
            }

            output.push(Msg {
                sender: self.own_party_index as u16,
                receiver: Some(i as u16 + 1),
                body: FeldmanVSS { 
                    vss: vss_result.0.clone(), 
                    share: (i + 1, share.clone()),
                    sender: self.own_party_index,
                    recipient: Address::Peer(i + 1),
                },
            })
        }

        let own_party_index = self.own_party_index.clone();
        let (parties_points, own_point): (Vec<(_, _)>, Vec<(_, _)>) = mapped_shares
            .into_iter()
            .partition(|(party, _)| *party != own_party_index);
        let own_point = own_point[0].1.clone();
        let other_points = parties_points
            .into_iter()
            .map(|(party, share_xy)| (party, share_xy))
            .collect::<HashMap<_, _>>();

        Ok(Round3 {
            keys: self.keys,

            y_vec: received_decom.into_iter().map(|d| d.y_i).collect(),
            bc_vec: self.commitments,

            own_vss: vss_result.0.clone(),
            own_share: (self.own_party_index, vss_result.1[usize::from(self.own_party_index - 1)].clone()),

            own_party_index: self.own_party_index,
            other_parties: self.other_parties.clone(),
            key_params: self.key_params,
            own_point: own_point.clone(),
            other_points,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<KeyGenDecommit>> {
        containers::BroadcastMsgsStore::new(i, n)
    }

}
