use curv::{
    elliptic::curves::secp256_k1::Secp256k1, 
    BigInt, 
};
use std::convert::TryFrom;
use round_based::{
    Msg,
    containers::{
        self, 
        push::Push,
        Store, 
        BroadcastMsgs,
    },
};

use crate::{
    utilities::mta::{MessageA, MessageB}, 
    protocols::gg_2020::party_i::{
        SignBroadcastPhase1, 
        SignDecommitPhase1
    },
    protocols::gg_2020::{
        party_i::SignKeys,
        state_machine::keygen::local_key::LocalKey,
        state_machine::sign::{
            error::sign_round_error::SignRoundError,
            messages::{
                GammaI,
                WI,
            },
            rounds::round_2::Round2,
            types::SignRoundResult,
        }, 
        ErrorType,
        
    }
};

pub struct Round1 {
    pub(super) i: u16,
    pub(super) s_l: Vec<u16>,
    pub(super) local_key: LocalKey<Secp256k1>,
    pub(super) m_a: (MessageA, BigInt),
    pub(super) sign_keys: SignKeys,
    pub(super) phase1_com: SignBroadcastPhase1,
    pub(super) phase1_decom: SignDecommitPhase1,
}

impl Round1 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<(MessageA, SignBroadcastPhase1)>,
        mut output: O,
    ) -> SignRoundResult<Round2>
    where
        O: Push<Msg<(GammaI, WI)>>,
    {
        let (m_a_vec, bc_vec): (Vec<_>, Vec<_>) = input
            .into_vec_including_me((self.m_a.0.clone(), self.phase1_com.clone()))
            .into_iter()
            .unzip();

        let mut m_b_gamma_vec = Vec::new();
        let mut beta_vec = Vec::new();
        let mut m_b_w_vec = Vec::new();
        let mut ni_vec = Vec::new();

        let ttag = self.s_l.len();
        let l_s: Vec<_> = self
            .s_l
            .iter()
            .cloned()
            .map(|i| usize::from(i) - 1)
            .collect();
        let i = usize::from(self.i - 1);
        for j in 0..ttag - 1 {
            let ind = if j < i { j } else { j + 1 };

            let (m_b_gamma, beta_gamma, _beta_randomness, _beta_tag) = MessageB::b(
                &self.sign_keys.gamma_i,
                &self.local_key.paillier_key_vec[l_s[ind]],
                m_a_vec[ind].clone(),
                &self.local_key.h1_h2_n_tilde_vec,
            )
            .map_err(|e| {
                SignRoundError::Round1(ErrorType {
                    error_type: e.to_string(),
                    bad_actors: vec![],
                })
            })?;

            let (m_b_w, beta_wi, _, _) = MessageB::b(
                &self.sign_keys.w_i,
                &self.local_key.paillier_key_vec[l_s[ind]],
                m_a_vec[ind].clone(),
                &self.local_key.h1_h2_n_tilde_vec,
            )
            .map_err(|e| {
                SignRoundError::Round1(ErrorType {
                    error_type: e.to_string(),
                    bad_actors: vec![],
                })
            })?;

            m_b_gamma_vec.push(m_b_gamma);
            beta_vec.push(beta_gamma);
            m_b_w_vec.push(m_b_w);
            ni_vec.push(beta_wi);
        }

        let party_indices = (1..=self.s_l.len())
            .map(|j| u16::try_from(j).unwrap())
            .filter(|&j| j != self.i);
        for ((j, gamma_i), w_i) in party_indices.zip(m_b_gamma_vec).zip(m_b_w_vec) {
            output.push(Msg {
                sender: self.i,
                receiver: Some(j),
                body: (GammaI(gamma_i.clone()), WI(w_i.clone())),
            });
        }

        Ok(Round2 {
            i: self.i,
            s_l: self.s_l,
            local_key: self.local_key,
            sign_keys: self.sign_keys,
            m_a: self.m_a,
            beta_vec,
            ni_vec,
            bc_vec,
            m_a_vec,
            phase1_decom: self.phase1_decom,
        })
    }

    pub fn expects_messages(
        i: u16,
        n: u16,
    ) -> Store<BroadcastMsgs<(MessageA, SignBroadcastPhase1)>> {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}
