use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use sha2::Sha256;
use round_based::containers::push::Push;
use round_based::containers::{self, P2PMsgs, Store};
use round_based::Msg;

use crate::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::{
    messages::{
        broadcast_message::KeyGenBroadcastMessage,
        feldman_vss::FeldmanVSS,
        parameters::Parameters,
    },
    types::ProceedResult, 
    rounds::round_4::Round4, 
    error::proceed_error::ProceedError,
    party_i::keys::Keys,    
};

pub struct Round3 {
    pub(super) keys: Keys,

    pub(super) y_vec: Vec<Point<Secp256k1>>,
    pub(super) bc_vec: Vec<KeyGenBroadcastMessage>,

    pub(super) own_vss: VerifiableSS<Secp256k1>,
    pub(super) own_share: Scalar<Secp256k1>,

    pub(super) party_i: u16,
    pub(super) t: u16,
    pub(super) n: u16,
}

impl Round3 {
    pub fn proceed<O>(
        self,
        input: P2PMsgs<FeldmanVSS>,
        mut output: O,
    ) -> ProceedResult<Round4>
    where
        O: Push<Msg<DLogProof<Secp256k1, Sha256>>>,
    {
        let params = Parameters {
            threshold: self.t,
            share_count: self.n,
        };
        
        let feldman_vss_list: Vec<FeldmanVSS> = input
            .into_vec_including_me(FeldmanVSS{vss:self.own_vss.clone(), share: self.own_share.clone()});

        let (shared_keys, dlog_proof) = self
            .keys
            .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                &params,
                &self.y_vec,
                // &party_shares,
                // &vss_schemes,
                &feldman_vss_list,
                self.party_i.into(),
            )
            .map_err(ProceedError::Round3VerifyVssConstruct)?;

        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: dlog_proof.clone(),
        });

        let vss_schemes = feldman_vss_list.iter().map(|x| x.vss.clone()).collect();

        Ok(Round4 {
            keys: self.keys.clone(),
            y_vec: self.y_vec.clone(),
            bc_vec: self.bc_vec,
            shared_keys,
            own_dlog_proof: dlog_proof,
            vss_vec: vss_schemes,

            party_i: self.party_i,
            t: self.t,
            n: self.n,
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
