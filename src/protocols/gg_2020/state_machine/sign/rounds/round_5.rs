use curv::elliptic::curves::{
    secp256_k1::Secp256k1, 
    Point, 
    Scalar
};
use round_based::{
    Msg,
    containers::{
        self, 
        push::Push,
        BroadcastMsgs, 
        Store
    },
};

use crate::utilities::{
    mta::MessageA,
    zk_pdl_with_slack::PDLwSlackProof
};


use crate::protocols::gg_2020::{
    ErrorType,
    party_i::{
        LocalSignature, 
        SignKeys, 
    },
    state_machine::keygen::local_key::LocalKey,
    state_machine::sign::{
        messages::{
            HEGProof, 
            SI,
            RDash,
        },
        CompletedOfflineStage, 
        error::sign_round_error::SignRoundError,
        rounds::round_6::Round6,
        types::SignRoundResult,
    },
    
};


pub struct Round5 {
    pub(super) i: u16,
    pub(super) s_l: Vec<u16>,
    pub(super) local_key: LocalKey<Secp256k1>,
    pub(super) sign_keys: SignKeys,
    pub(super) t_vec: Vec<Point<Secp256k1>>,
    pub(super) m_a_vec: Vec<MessageA>,
    pub(super) t_i: Point<Secp256k1>,
    pub(super) l_i: Scalar<Secp256k1>,
    pub(super) sigma_i: Scalar<Secp256k1>,
    pub(super) R: Point<Secp256k1>,
    pub(super) R_dash: Point<Secp256k1>,
    pub(super) phase5_proofs_vec: Vec<PDLwSlackProof>,
}

impl Round5 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<(RDash, Vec<PDLwSlackProof>)>,
        mut output: O,
    ) -> SignRoundResult<Round6>
    where
        O: Push<Msg<(SI, HEGProof)>>,
    {
        let (r_dash_vec, pdl_proof_mat_inc_me): (Vec<_>, Vec<_>) = input
            .into_vec_including_me((RDash(self.R_dash), self.phase5_proofs_vec))
            .into_iter()
            .map(|(r_dash, pdl_proof)| (r_dash.0, pdl_proof))
            .unzip();

        let l_s: Vec<_> = self
            .s_l
            .iter()
            .cloned()
            .map(|i| usize::from(i) - 1)
            .collect();
        let ttag = self.s_l.len();
        for i in 0..ttag {
            LocalSignature::phase5_verify_pdl(
                &pdl_proof_mat_inc_me[i],
                &r_dash_vec[i],
                &self.R,
                &self.m_a_vec[i].c,
                &self.local_key.paillier_key_vec[l_s[i]],
                &self.local_key.h1_h2_n_tilde_vec,
                &l_s,
                i,
            )
            .map_err(SignRoundError::Round5)?;
        }
        LocalSignature::phase5_check_R_dash_sum(&r_dash_vec).map_err(|e| {
            SignRoundError::Round5(ErrorType {
                error_type: e.to_string(),
                bad_actors: vec![],
            })
        })?;

        let (S_i, homo_elgamal_proof) = LocalSignature::phase6_compute_S_i_and_proof_of_consistency(
            &self.R,
            &self.t_i,
            &self.sigma_i,
            &self.l_i,
        );

        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: (SI(S_i.clone()), HEGProof(homo_elgamal_proof.clone())),
        });

        Ok(Round6 {
            S_i,
            homo_elgamal_proof,
            s_l: self.s_l,
            protocol_output: CompletedOfflineStage {
                i: self.i,
                local_key: self.local_key,
                sign_keys: self.sign_keys,
                t_vec: self.t_vec,
                R: self.R,
                sigma_i: self.sigma_i,
            },
        })
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<(RDash, Vec<PDLwSlackProof>)>> {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}
