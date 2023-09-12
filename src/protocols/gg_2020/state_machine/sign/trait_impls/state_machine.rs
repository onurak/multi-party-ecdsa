use std::mem::replace;
use std::time::Duration;
use round_based::{
    containers::MessageStore, 
    Msg, 
    StateMachine
};

use crate::protocols::gg_2020::state_machine::sign::{
    error::sign_error::SignError,
    messages::{
        OfflineM,
        OfflineProtocolMessage,
    },
    stages::offline_stage::OfflineStage,
    stages::offline_stage::OfflineR,
    rounds::CompletedOfflineStage
};

impl StateMachine for OfflineStage {
    type MessageBody = OfflineProtocolMessage;
    type Err = SignError;
    type Output = CompletedOfflineStage;

    fn handle_incoming(&mut self, msg: Msg<Self::MessageBody>) -> Result<(), Self::Err> {
        let current_round = self.current_round();

        match msg.body {
            OfflineProtocolMessage(OfflineM::M1(m)) => {
                let store = self
                    .msgs1
                    .as_mut()
                    .ok_or(SignError::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 1,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(SignError::HandleMessage)?;
            }
            OfflineProtocolMessage(OfflineM::M2(m)) => {
                let store = self
                    .msgs2
                    .as_mut()
                    .ok_or(SignError::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 2,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(SignError::HandleMessage)?;
            }
            OfflineProtocolMessage(OfflineM::M3(m)) => {
                let store = self
                    .msgs3
                    .as_mut()
                    .ok_or(SignError::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 2,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(SignError::HandleMessage)?;
            }
            OfflineProtocolMessage(OfflineM::M4(m)) => {
                let store = self
                    .msgs4
                    .as_mut()
                    .ok_or(SignError::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 2,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(SignError::HandleMessage)?;
            }
            OfflineProtocolMessage(OfflineM::M5(m)) => {
                let store = self
                    .msgs5
                    .as_mut()
                    .ok_or(SignError::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 2,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(SignError::HandleMessage)?;
            }
            OfflineProtocolMessage(OfflineM::M6(m)) => {
                let store = self
                    .msgs6
                    .as_mut()
                    .ok_or(SignError::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 2,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(SignError::HandleMessage)?;
            }
        }
        self.proceed_round(false)
    }

    fn message_queue(&mut self) -> &mut Vec<Msg<Self::MessageBody>> {
        &mut self.msgs_queue.0
    }

    fn wants_to_proceed(&self) -> bool {
        let store1_wants_more = self.msgs1.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store2_wants_more = self.msgs2.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store3_wants_more = self.msgs3.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store4_wants_more = self.msgs4.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store5_wants_more = self.msgs5.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store6_wants_more = self.msgs6.as_ref().map(|s| s.wants_more()).unwrap_or(false);

        match &self.round {
            OfflineR::R0(_) => true,
            OfflineR::R1(_) => !store1_wants_more,
            OfflineR::R2(_) => !store2_wants_more,
            OfflineR::R3(_) => !store3_wants_more,
            OfflineR::R4(_) => !store4_wants_more,
            OfflineR::R5(_) => !store5_wants_more,
            OfflineR::R6(_) => !store6_wants_more,
            OfflineR::Finished(_) | OfflineR::Gone => false,
        }
    }

    fn proceed(&mut self) -> Result<(), Self::Err> {
        self.proceed_round(true)
    }

    fn round_timeout(&self) -> Option<Duration> {
        None
    }

    fn round_timeout_reached(&mut self) -> Self::Err {
        panic!("no timeout was set")
    }

    fn is_finished(&self) -> bool {
        matches!(&self.round, OfflineR::Finished(_))
    }

    fn pick_output(&mut self) -> Option<Result<Self::Output, Self::Err>> {
        match self.round {
            OfflineR::Finished(_) => (),
            OfflineR::Gone => return Some(Err(SignError::DoublePickOutput)),
            _ => return None,
        }

        match replace(&mut self.round, OfflineR::Gone) {
            OfflineR::Finished(result) => Some(Ok(result)),
            _ => unreachable!("guaranteed by match expression above"),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            OfflineR::R0(_) => 0,
            OfflineR::R1(_) => 1,
            OfflineR::R2(_) => 2,
            OfflineR::R3(_) => 3,
            OfflineR::R4(_) => 4,
            OfflineR::R5(_) => 5,
            OfflineR::R6(_) => 6,
            OfflineR::Finished(_) | OfflineR::Gone => 7,
        }
    }

    fn total_rounds(&self) -> Option<u16> {
        Some(6)
    }

    fn party_ind(&self) -> u16 {
        self.party_i
    }

    fn parties(&self) -> u16 {
        self.party_n
    }
}
