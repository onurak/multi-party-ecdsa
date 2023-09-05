use std::collections::BTreeSet;

use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use sha2::Sha256;
use round_based::containers::push::Push;
use round_based::containers::{self, P2PMsgs, Store};
use round_based::Msg;

use crate::protocols::gg_2020::state_machine::keygen::{
    messages::{
        broadcast::KeyGenBroadcast,
        feldman_vss::FeldmanVSS,
        parameters::Parameters,
        proof::Proof,
    },
    types::ProceedResult, 
    rounds::round_4::Round4, 
    error::proceed_error::ProceedError,
    party_i::keys::Keys,    
};

pub struct Round3 {
    pub(super) keys: Keys,

    pub(super) y_vec: Vec<Point<Secp256k1>>,
    pub(super) bc_vec: Vec<KeyGenBroadcast>,

    pub(super) own_vss: VerifiableSS<Secp256k1>,
    pub(super) own_share: Scalar<Secp256k1>,

    pub(super) own_party_index: u16,
    pub(super) other_parties: BTreeSet<u16>,
    pub(super) key_params: Parameters,
}

impl Round3 {
    pub fn proceed<O>(
        self,
        input: P2PMsgs<FeldmanVSS>,
        mut output: O,
    ) -> ProceedResult<Round4>
    where
        O: Push<Msg<Proof>>,
    {
        
        let feldman_vss_list: Vec<FeldmanVSS> = input
            .into_vec_including_me(FeldmanVSS{vss:self.own_vss.clone(), share: self.own_share.clone()});

        let (shared_keys, proof) = self
            .keys
            .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                &self.key_params,
                &self.y_vec,
                // &party_shares,
                // &vss_schemes,
                &feldman_vss_list,
                self.own_party_index.into(),
            )
            .map_err(ProceedError::Round3VerifyVssConstruct)?;

        output.push(Msg {
            sender: self.own_party_index,
            receiver: None,
            body: proof.clone(),
        });

        let vss_schemes = feldman_vss_list.iter().map(|x| x.vss.clone()).collect();

        Ok(Round4 {
            keys: self.keys.clone(),
            y_vec: self.y_vec.clone(),
            bc_vec: self.bc_vec,
            shared_keys,
            own_proof: proof,
            vss_vec: vss_schemes,

            own_party_index: self.own_party_index,
            other_parties: self.other_parties.clone(),
            key_params: self.key_params,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(
        i: u16,
        n: u16,
    ) -> Store<P2PMsgs<FeldmanVSS>> {
        containers::P2PMsgsStore::new(i, n)
    }
}
