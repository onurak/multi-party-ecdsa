use std::fmt;

use crate::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::{
    Keygen, 
    R
};



impl fmt::Debug for Keygen {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let current_round = match &self.round {
            R::Round0(_) => "0",
            R::Round1(_) => "1",
            R::Round2(_) => "2",
            R::Round3(_) => "3",
            R::Round4(_) => "4",
            R::Final(_) => "[Final]",
            R::Gone => "[Gone]",
        };
        let msgs1 = match self.msgs1.as_ref() {
            Some(msgs) => format!("[{}/{}]", msgs.messages_received(), msgs.messages_total()),
            None => "[None]".into(),
        };
        let msgs2 = match self.msgs2.as_ref() {
            Some(msgs) => format!("[{}/{}]", msgs.messages_received(), msgs.messages_total()),
            None => "[None]".into(),
        };
        let msgs3 = match self.msgs3.as_ref() {
            Some(msgs) => format!("[{}/{}]", msgs.messages_received(), msgs.messages_total()),
            None => "[None]".into(),
        };
        let msgs4 = match self.msgs4.as_ref() {
            Some(msgs) => format!("[{}/{}]", msgs.messages_received(), msgs.messages_total()),
            None => "[None]".into(),
        };
        write!(
            f,
            "{{Keygen at round={} msgs1={} msgs2={} msgs3={} msgs4={} queue=[len={}]}}",
            current_round,
            msgs1,
            msgs2,
            msgs3,
            msgs4,
            self.msgs_queue.len()
        )
    }
}

