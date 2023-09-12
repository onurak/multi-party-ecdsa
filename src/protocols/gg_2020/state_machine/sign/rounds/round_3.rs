use curv::{
    elliptic::curves::{
        secp256_k1::Secp256k1, 
        Point, 
        Scalar
    }, 
    BigInt, 
    cryptographic_primitives::proofs::sigma_valid_pedersen::PedersenProof
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
use sha2::Sha256;

use crate::{
    utilities::mta::{
        MessageA, 
        MessageB
    }, 
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
            },
            rounds::round_4::Round4,
            rounds::IteratorExt,
            types::SignRoundResult,
        }, 
        ErrorType,
        
    }
};


pub struct Round3 {
    pub(super) i: u16,
    pub(super) s_l: Vec<u16>,
    pub(super) local_key: LocalKey<Secp256k1>,
    pub(super) sign_keys: SignKeys,
    pub(super) m_a: (MessageA, BigInt),
    pub(super) mb_gamma_s: Vec<MessageB>,
    pub(super) bc_vec: Vec<SignBroadcastPhase1>,
    pub(super) m_a_vec: Vec<MessageA>,
    pub(super) delta_i: Scalar<Secp256k1>,
    pub(super) t_i: Point<Secp256k1>,
    pub(super) l_i: Scalar<Secp256k1>,
    pub(super) sigma_i: Scalar<Secp256k1>,
    pub(super) t_i_proof: PedersenProof<Secp256k1, Sha256>,

    pub(super) phase1_decom: SignDecommitPhase1,
}

impl Round3 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<(DeltaI, TI, TIProof)>,
        mut output: O,
    ) -> SignRoundResult<Round4>
    where
        O: Push<Msg<SignDecommitPhase1>>,
    {
        let (delta_vec, t_vec, t_proof_vec) = input
            .into_vec_including_me((
                DeltaI(self.delta_i),
                TI(self.t_i.clone()),
                TIProof(self.t_i_proof),
            ))
            .into_iter()
            .map(|(delta_i, t_i, t_i_proof)| (delta_i.0, t_i.0, t_i_proof.0))
            .unzip3();

        for i in 0..t_vec.len() {
            assert_eq!(t_vec[i], t_proof_vec[i].com);
        }

        let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);
        let ttag = self.s_l.len();
        for proof in t_proof_vec.iter().take(ttag) {
            PedersenProof::verify(proof).map_err(|e| {
                SignRoundError::Round3(ErrorType {
                    error_type: e.to_string(),
                    bad_actors: vec![],
                })
            })?;
        }

        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: self.phase1_decom.clone(),
        });

        Ok(Round4 {
            i: self.i,
            s_l: self.s_l,
            local_key: self.local_key,
            sign_keys: self.sign_keys,
            m_a: self.m_a,
            mb_gamma_s: self.mb_gamma_s,
            bc_vec: self.bc_vec,
            m_a_vec: self.m_a_vec,
            t_i: self.t_i,
            l_i: self.l_i,
            sigma_i: self.sigma_i,
            phase1_decom: self.phase1_decom,
            delta_inv,
            t_vec,
        })
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<(DeltaI, TI, TIProof)>> {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}
