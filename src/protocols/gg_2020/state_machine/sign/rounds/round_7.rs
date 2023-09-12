use curv::BigInt;
use crate::protocols::gg_2020::party_i::{
    LocalSignature, 
    SignatureRecid,
};
use crate::protocols::gg_2020::state_machine::sign::{
    types::SignRoundResult,
    error::sign_round_error::SignRoundError
};

use super::{CompletedOfflineStage, PartialSignature};


#[derive(Clone)]
pub struct Round7 {
    pub(super) local_signature: LocalSignature,
}

impl Round7 {
    pub fn new(
        message: &BigInt,
        completed_offline_stage: CompletedOfflineStage,
    ) -> SignRoundResult<(Self, PartialSignature)> {
        let local_signature = LocalSignature::phase7_local_sig(
            &completed_offline_stage.sign_keys.k_i,
            message,
            &completed_offline_stage.R,
            &completed_offline_stage.sigma_i,
            &completed_offline_stage.local_key.public_key,
        );
        let partial = PartialSignature(local_signature.s_i.clone());
        Ok((Self { local_signature }, partial))
    }

    pub fn proceed_manual(self, sigs: &[PartialSignature]) -> SignRoundResult<SignatureRecid> {
        let sigs = sigs.iter().map(|s_i| s_i.0.clone()).collect::<Vec<_>>();
        self.local_signature
            .output_signature(&sigs)
            .map_err(SignRoundError::Round7)
    }
}
