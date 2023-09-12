use std::fmt;

use round_based::containers::{BroadcastMsgsStore, MessageStore, P2PMsgsStore};

use crate::protocols::gg_2020::state_machine::sign::stages::offline_stage::{self, OfflineStage};

impl fmt::Debug for OfflineStage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        OfflineStageProgress::from(self).fmt(f)
    }
}

#[derive(Debug)]
pub struct OfflineStageProgress {
    round: OfflineR,

    round1_msgs: ReceivedMessages,
    round2_msgs: ReceivedMessages,
    round3_msgs: ReceivedMessages,
    round4_msgs: ReceivedMessages,
    round5_msgs: ReceivedMessages,

    msgs_queue: OutgoingMessages,
}

impl From<&OfflineStage> for OfflineStageProgress {
    fn from(state: &OfflineStage) -> Self {
        Self {
            round: match &state.round {
                offline_stage::OfflineR::R0(_) => OfflineR::R0,
                offline_stage::OfflineR::R1(_) => OfflineR::R1,
                offline_stage::OfflineR::R2(_) => OfflineR::R2,
                offline_stage::OfflineR::R3(_) => OfflineR::R3,
                offline_stage::OfflineR::R4(_) => OfflineR::R4,
                offline_stage::OfflineR::R5(_) => OfflineR::R5,
                offline_stage::OfflineR::R6(_) => OfflineR::R6,
                offline_stage::OfflineR::Finished(_) => OfflineR::Finished,
                offline_stage::OfflineR::Gone => OfflineR::Gone,
            },

            round1_msgs: ReceivedMessages::from_broadcast(state.msgs1.as_ref()),
            round2_msgs: ReceivedMessages::from_p2p(state.msgs2.as_ref()),
            round3_msgs: ReceivedMessages::from_broadcast(state.msgs3.as_ref()),
            round4_msgs: ReceivedMessages::from_broadcast(state.msgs4.as_ref()),
            round5_msgs: ReceivedMessages::from_broadcast(state.msgs5.as_ref()),

            msgs_queue: OutgoingMessages {
                len: state.msgs_queue.0.len(),
            },
        }
    }
}

#[derive(Debug)]
pub enum OfflineR {
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    Finished,
    Gone,
}

pub enum ContainerType {
    P2P,
    Broadcast,
}

pub struct ReceivedMessages(Option<MessagesContainer>);

pub struct MessagesContainer {
    ty: ContainerType,
    total: usize,
    waiting_for: Vec<u16>,
}

impl ReceivedMessages {
    fn from_broadcast<T>(store: Option<&BroadcastMsgsStore<T>>) -> Self {
        match store {
            Some(store) => ReceivedMessages(Some(MessagesContainer {
                ty: ContainerType::Broadcast,
                total: store.messages_total(),
                waiting_for: store.blame().1,
            })),
            None => ReceivedMessages(None),
        }
    }
    fn from_p2p<T>(store: Option<&P2PMsgsStore<T>>) -> Self {
        match store {
            Some(store) => ReceivedMessages(Some(MessagesContainer {
                ty: ContainerType::P2P,
                total: store.messages_total(),
                waiting_for: store.blame().1,
            })),
            None => ReceivedMessages(None),
        }
    }
}

impl fmt::Debug for ReceivedMessages {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            Some(container) => {
                let ty = match container.ty {
                    ContainerType::Broadcast => "bc",
                    ContainerType::P2P => "p2p",
                };
                write!(
                    f,
                    "[{} {}/{}]",
                    ty,
                    container.total - container.waiting_for.len(),
                    container.total
                )
            }
            None => write!(f, "[gone]"),
        }
    }
}

#[derive(Debug)]
pub struct OutgoingMessages {
    len: usize,
}
