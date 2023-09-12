#![allow(non_snake_case)]

use std::iter;
use sha2::Sha256;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, };
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use round_based::containers::{self, BroadcastMsgs, Store};

use crate::protocols::gg_2020::{
    party_i::LocalSignature,
    state_machine::sign::{
        messages::{
            HEGProof, 
            SI,
        },
        CompletedOfflineStage, 
        error::sign_round_error::SignRoundError,
    },
    
};

pub struct Round6 {
    pub(super) S_i: Point<Secp256k1>,
    pub(super) homo_elgamal_proof: HomoELGamalProof<Secp256k1, Sha256>,
    pub(super) s_l: Vec<u16>,
    /// Round 6 guards protocol output until final checks are taken the place
    pub(super) protocol_output: CompletedOfflineStage,
}

impl Round6 {
    pub fn proceed(
        self,
        input: BroadcastMsgs<(SI, HEGProof)>,
    ) -> Result<CompletedOfflineStage, SignRoundError> {
        let (S_i_vec, hegp_vec): (Vec<_>, Vec<_>) = input
            .into_vec_including_me((SI(self.S_i), HEGProof(self.homo_elgamal_proof)))
            .into_iter()
            .map(|(s_i, hegp_i)| (s_i.0, hegp_i.0))
            .unzip();
        let R_vec: Vec<_> = iter::repeat(self.protocol_output.R.clone())
            .take(self.s_l.len())
            .collect();

        LocalSignature::phase6_verify_proof(
            &S_i_vec,
            &hegp_vec,
            &R_vec,
            &self.protocol_output.t_vec,
        )
        .map_err(SignRoundError::Round6VerifyProof)?;
        LocalSignature::phase6_check_S_i_sum(&self.protocol_output.local_key.public_key, &S_i_vec)
            .map_err(SignRoundError::Round6CheckSig)?;

        Ok(self.protocol_output)
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<(SI, HEGProof)>> {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}
