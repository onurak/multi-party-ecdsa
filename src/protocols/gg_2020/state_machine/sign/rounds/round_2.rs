use curv::{
    elliptic::curves::{
        secp256_k1::Secp256k1, 
        Scalar
    }, 
    BigInt, 
};
use round_based::{
    Msg,
    containers::{
        self, 
        push::Push,
        Store, 
        P2PMsgs,
    },
};

use crate::{
    utilities::mta::MessageA, 
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
                DeltaI,
                TI,
                TIProof,
                GammaI,
                WI,
                
            },
            rounds::round_3::Round3,
            types::SignRoundResult,
        }, 
        ErrorType,
        
    }
};

pub struct Round2 {
    pub(super) i: u16,
    pub(super) s_l: Vec<u16>,
    pub(super) local_key: LocalKey<Secp256k1>,
    pub(super) sign_keys: SignKeys,
    pub(super) m_a: (MessageA, BigInt),
    pub(super) beta_vec: Vec<Scalar<Secp256k1>>,
    pub(super) ni_vec: Vec<Scalar<Secp256k1>>,
    pub(super) bc_vec: Vec<SignBroadcastPhase1>,
    pub(super) m_a_vec: Vec<MessageA>,
    pub(super) phase1_decom: SignDecommitPhase1,
}

impl Round2 {
    pub fn proceed<O>(self, input_p2p: P2PMsgs<(GammaI, WI)>, mut output: O) -> SignRoundResult<Round3>
    where
        O: Push<Msg<(DeltaI, TI, TIProof)>>, // TODO: unify TI and TIProof
    {
        let (m_b_gamma_s, m_b_w_s): (Vec<_>, Vec<_>) = input_p2p
            .into_vec()
            .into_iter()
            .map(|(gamma_i, w_i)| (gamma_i.0, w_i.0))
            .unzip();

        let mut alpha_vec = Vec::new();
        let mut miu_vec = Vec::new();

        let ttag = self.s_l.len();
        let index = usize::from(self.i) - 1;
        let l_s: Vec<_> = self
            .s_l
            .iter()
            .cloned()
            .map(|i| usize::from(i) - 1)
            .collect();
        let g_w_vec = SignKeys::g_w_vec(
            &self.local_key.pk_vec[..],
            &l_s[..],
            &self.local_key.vss_scheme,
        );
        for j in 0..ttag - 1 {
            let ind = if j < index { j } else { j + 1 };
            let m_b = m_b_gamma_s[j].clone();

            let alpha_ij_gamma = m_b
                .verify_proofs_get_alpha(&self.local_key.paillier_dk, &self.sign_keys.k_i)
                .map_err(|e| {
                    SignRoundError::Round3(ErrorType {
                        error_type: e.to_string(),
                        bad_actors: vec![],
                    })
                })?;
            let m_b = m_b_w_s[j].clone();
            let alpha_ij_wi = m_b
                .verify_proofs_get_alpha(&self.local_key.paillier_dk, &self.sign_keys.k_i)
                .map_err(|e| {
                    SignRoundError::Round3(ErrorType {
                        error_type: e.to_string(),
                        bad_actors: vec![],
                    })
                })?;
            assert_eq!(m_b.b_proof.pk, g_w_vec[ind]); //TODO: return error

            alpha_vec.push(alpha_ij_gamma.0);
            miu_vec.push(alpha_ij_wi.0);
        }

        let delta_i = self.sign_keys.phase2_delta_i(&alpha_vec, &self.beta_vec);

        let sigma_i = self.sign_keys.phase2_sigma_i(&miu_vec, &self.ni_vec);
        let (t_i, l_i, t_i_proof) = SignKeys::phase3_compute_t_i(&sigma_i);
        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: (
                DeltaI(delta_i.clone()),
                TI(t_i.clone()),
                TIProof(t_i_proof.clone()),
            ),
        });

        Ok(Round3 {
            i: self.i,
            s_l: self.s_l,
            local_key: self.local_key,
            sign_keys: self.sign_keys,
            m_a: self.m_a,
            mb_gamma_s: m_b_gamma_s,
            bc_vec: self.bc_vec,
            m_a_vec: self.m_a_vec,
            delta_i,
            t_i,
            l_i,
            sigma_i,
            t_i_proof,
            phase1_decom: self.phase1_decom,
        })
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<P2PMsgs<(GammaI, WI)>> {
        containers::P2PMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}
