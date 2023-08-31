use round_based::containers::MessageStore;

use crate::protocols::gg_2020::state_machine::{
    traits::RoundBlame, 
    keygen::{
        Keygen, 
        R
    }
};


impl RoundBlame for Keygen {
    /// Returns number of unwilling parties and a vector of their party indexes.
    fn round_blame(&self) -> (u16, Vec<u16>) {
        let store1_blame = self.msgs1.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store2_blame = self.msgs2.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store3_blame = self.msgs3.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store4_blame = self.msgs4.as_ref().map(|s| s.blame()).unwrap_or_default();

        let default = (0, vec![]);
        match &self.round {
            R::Round0(_) => default,
            R::Round1(_) => store1_blame,
            R::Round2(_) => store2_blame,
            R::Round3(_) => store3_blame,
            R::Round4(_) => store4_blame,
            R::Final(_) | R::Gone => default,
        }
    }
}

