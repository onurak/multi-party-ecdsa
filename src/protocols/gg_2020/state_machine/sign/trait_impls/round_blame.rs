use round_based::containers::MessageStore;

use crate::protocols::gg_2020::state_machine::{
    sign::{
        stages::offline_stage::OfflineStage, 
        stages::offline_stage::OfflineR, 
    },
    traits::RoundBlame,
};


impl RoundBlame for OfflineStage {
    /// RoundBlame returns number of unwilling parties and a vector of their party indexes.
    fn round_blame(&self) -> (u16, Vec<u16>) {
        let store1_blame = self.msgs1.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store2_blame = self.msgs2.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store3_blame = self.msgs3.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store4_blame = self.msgs4.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store5_blame = self.msgs5.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store6_blame = self.msgs6.as_ref().map(|s| s.blame()).unwrap_or_default();

        let default = (0, vec![]);
        match &self.round {
            OfflineR::R0(_) => default,
            OfflineR::R1(_) => store1_blame,
            OfflineR::R2(_) => store2_blame,
            OfflineR::R3(_) => store3_blame,
            OfflineR::R4(_) => store4_blame,
            OfflineR::R5(_) => store5_blame,
            OfflineR::R6(_) => store6_blame,
            OfflineR::Finished(_) => store6_blame,
            OfflineR::Gone => default,
        }
    }
}
