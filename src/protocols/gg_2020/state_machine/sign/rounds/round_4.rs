use curv::{elliptic::curves::{
    secp256_k1::Secp256k1, 
    Point, 
    Scalar
}, BigInt};
use round_based::{
    Msg,
    containers::{
        self, 
        push::Push,
        BroadcastMsgs, 
        Store
    },
};

use crate::{
    utilities::{
        mta::{
            MessageA, MessageB
        },
        zk_pdl_with_slack::PDLwSlackProof
    }, 
    protocols::gg_2020::party_i::{
        SignBroadcastPhase1, 
        SignDecommitPhase1
    },
    protocols::gg_2020::{
        party_i::{
            LocalSignature, 
            SignKeys, 
        },
        state_machine::keygen::local_key::LocalKey,
        state_machine::sign::{
            error::sign_round_error::SignRoundError,
            messages::RDash,
            rounds::round_5::Round5,
            types::SignRoundResult,
        },
        
    }
};




pub struct Round4 {
    pub(super) i: u16,
    pub(super) s_l: Vec<u16>,
    pub(super) local_key: LocalKey<Secp256k1>,
    pub(super) sign_keys: SignKeys,
    pub(super) m_a: (MessageA, BigInt),
    pub(super) mb_gamma_s: Vec<MessageB>,
    pub(super) bc_vec: Vec<SignBroadcastPhase1>,
    pub(super) m_a_vec: Vec<MessageA>,
    pub(super) t_i: Point<Secp256k1>,
    pub(super) l_i: Scalar<Secp256k1>,
    pub(super) sigma_i: Scalar<Secp256k1>,
    pub(super) delta_inv: Scalar<Secp256k1>,
    pub(super) t_vec: Vec<Point<Secp256k1>>,
    pub(super) phase1_decom: SignDecommitPhase1,
}

impl Round4 {
    pub fn proceed<O>(
        self,
        decommit_round1: BroadcastMsgs<SignDecommitPhase1>,
        mut output: O,
    ) -> SignRoundResult<Round5>
    where
        O: Push<Msg<(RDash, Vec<PDLwSlackProof>)>>,
    {
        let decom_vec: Vec<_> = decommit_round1.into_vec_including_me(self.phase1_decom.clone());

        let ttag = self.s_l.len();
        let b_proof_vec: Vec<_> = (0..ttag - 1).map(|i| &self.mb_gamma_s[i].b_proof).collect();
        let R = SignKeys::phase4(
            &self.delta_inv,
            &b_proof_vec[..],
            decom_vec,
            &self.bc_vec,
            usize::from(self.i - 1),
        )
        .map_err(SignRoundError::Round5)?;

        let R_dash = &R * &self.sign_keys.k_i;

        // each party sends first message to all other parties
        let mut phase5_proofs_vec = Vec::new();
        let l_s: Vec<_> = self
            .s_l
            .iter()
            .cloned()
            .map(|i| usize::from(i) - 1)
            .collect();
        let index = usize::from(self.i - 1);
        for j in 0..ttag - 1 {
            let ind = if j < index { j } else { j + 1 };
            let proof = LocalSignature::phase5_proof_pdl(
                &R_dash,
                &R,
                &self.m_a.0.c,
                &self.local_key.paillier_key_vec[l_s[index]],
                &self.sign_keys.k_i,
                &self.m_a.1,
                &self.local_key.h1_h2_n_tilde_vec[l_s[ind]],
            );

            phase5_proofs_vec.push(proof);
        }

        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: (RDash(R_dash.clone()), phase5_proofs_vec.clone()),
        });

        Ok(Round5 {
            i: self.i,
            s_l: self.s_l,
            local_key: self.local_key,
            sign_keys: self.sign_keys,
            t_vec: self.t_vec,
            m_a_vec: self.m_a_vec,
            t_i: self.t_i,
            l_i: self.l_i,
            sigma_i: self.sigma_i,
            R,
            R_dash,
            phase5_proofs_vec,
        })
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<SignDecommitPhase1>> {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}