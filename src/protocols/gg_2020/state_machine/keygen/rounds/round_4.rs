use std::collections::BTreeSet;

use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point};
use sha2::Sha256;
use paillier::EncryptionKey;
use round_based::containers::{self, BroadcastMsgs, Store};
use zk_paillier::zkproofs::DLogStatement;

use crate::protocols::gg_2020::state_machine::keygen::party_i::party_to_point_map::PartyToPointMap;
use crate::protocols::gg_2020::state_machine::keygen::types::SecretShare;
use crate::protocols::gg_2020::state_machine::keygen::{
    messages::{
        broadcast::KeyGenBroadcast,
        parameters::Parameters,
        proof::Proof,
    },
    types::ProceedResult, 
    error::keygen_round_error::KeygenRoundError,
    party_i::keys::Keys,   
    party_i::shared_keys::SharedKeys,    
    local_key::LocalKey,
};

pub struct Round4 {
    pub(super) keys: Keys,
    pub(super) y_vec: Vec<Point<Secp256k1>>,
    pub(super) bc_vec: Vec<KeyGenBroadcast>,
    pub(super) shared_keys: SharedKeys,
    pub(super) own_proof: Proof,
    pub(super) vss_vec: Vec<VerifiableSS<Secp256k1>>,

    pub(super) own_party_index: usize,
    pub(super) other_parties: BTreeSet<usize>,
    pub(super) key_params: Parameters,
    pub(super) secret_share: SecretShare<Secp256k1>,
    pub(super) party_to_point_map: PartyToPointMap,
}

impl Round4 {
    pub fn proceed(
        self,
        input: BroadcastMsgs<Proof>,
    ) -> ProceedResult<LocalKey<Secp256k1>> {
        
        let dlog_proofs = input.into_vec_including_me(self.own_proof.clone());

        Keys::verify_dlog_proofs_check_against_vss(
            &self.key_params,
            &dlog_proofs,
            &self.y_vec,
            &self.vss_vec,
        )
        .map_err(KeygenRoundError::Round4VerifyDLogProof)?;
        let pk_vec = (0..self.key_params.share_count as usize)
            .map(|i| dlog_proofs[i].proof.pk.clone())
            .collect::<Vec<Point<Secp256k1>>>();

        let paillier_key_vec = (0..self.key_params.share_count)
            .map(|i| self.bc_vec[i as usize].e.clone())
            .collect::<Vec<EncryptionKey>>();
        let h1_h2_n_tilde_vec = self
            .bc_vec
            .iter()
            .map(|bc1| bc1.dlog_statement.clone())
            .collect::<Vec<DLogStatement>>();

        let (head, tail) = self.y_vec.split_at(1);
        let y_sum = tail.iter().fold(head[0].clone(), |acc, x| acc + x);

        let new_point_x = self.secret_share.0;

        let mut party_to_point_map = self.party_to_point_map.clone();
        if let Some(old_point_x) = party_to_point_map
            .points
            .insert(self.own_party_index, new_point_x)
        {
            // not an error if the correct value is inserted
            log::warn!(
                "Own party index was already mapped to point {} instead of {}",
                old_point_x,
                new_point_x
            );
        }

        let local_key = LocalKey {
            paillier_dk: self.keys.paillier_keys.dk,
            pk_vec,

            keys_linear: self.shared_keys.clone(),
            paillier_key_vec,
            h1_h2_n_tilde_vec,

            vss_scheme: self.vss_vec[usize::from(self.own_party_index - 1)].clone(),

            own_party_index: self.own_party_index,   
            other_parties: self.other_parties.clone(),         
            public_key: y_sum,
            key_params: self.key_params,
            secret_share: self.secret_share.clone(),
            party_to_point_map: party_to_point_map,
        };

        Ok(local_key)
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<Proof>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}
