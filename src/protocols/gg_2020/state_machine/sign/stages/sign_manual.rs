use curv::BigInt;

use crate::protocols::gg_2020::{
    party_i::SignatureRecid,
    state_machine::sign::{
        error::sign_local_complete_error::SignLocalCompleteError,
        rounds::{
            CompletedOfflineStage, 
            PartialSignature,
            round_7::Round7
        },
    },
};

#[derive(Clone)]
pub struct SignManual {
    state: Round7,
}

impl SignManual {
    pub fn new(
        message: BigInt,
        completed_offline_stage: CompletedOfflineStage,
    ) -> Result<(Self, PartialSignature), SignLocalCompleteError> {
        Round7::new(&message, completed_offline_stage)
            .map(|(state, m)| (Self { state }, m))
            .map_err(SignLocalCompleteError::LocalSigning)
    }

    /// `sigs` must not include partial signature produced by local party (only partial signatures produced
    /// by other parties)
    pub fn complete(self, sigs: &[PartialSignature]) -> Result<SignatureRecid, SignLocalCompleteError> {
        self.state
            .proceed_manual(sigs)
            .map_err(SignLocalCompleteError::CompleteSigning)
    }
}

