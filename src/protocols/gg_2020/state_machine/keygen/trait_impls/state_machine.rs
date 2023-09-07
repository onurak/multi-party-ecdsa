use std::mem::replace;
use std::time::Duration;
use curv::elliptic::curves::secp256_k1::Secp256k1;
use round_based::containers::*;
use round_based::{Msg, StateMachine};

use crate::protocols::gg_2020::state_machine::keygen::messages::address::Address;
use crate::protocols::gg_2020::state_machine::keygen::{
    Keygen,
    local_key::LocalKey,
    messages::{
        ProtocolMessage,
        M,
        proof::Proof,
    },
    types::KeygenResult,
    error::keygen_error::KeygenError,
    R,
};



impl StateMachine for Keygen {
    type MessageBody = ProtocolMessage;
    type Err = KeygenError;
    type Output = LocalKey<Secp256k1>;

    fn handle_incoming(&mut self, msg: Msg<ProtocolMessage>) -> KeygenResult<()> {
        let current_round = self.current_round();

        match msg.body {
            ProtocolMessage(M::Round1(m)) => {
                let store = self
                    .msgs1
                    .as_mut()
                    .ok_or(KeygenError::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 1,
                    })?;

                let mut m_mut = m.clone();
                m_mut.sender = msg.sender as usize;
                m_mut.recipient = Address::Broadcast;
                if let Some(receiver) = msg.receiver {
                    m_mut.recipient = Address::Peer(receiver as usize);
                }

                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m_mut,
                    })
                    .map_err(KeygenError::HandleMessage)?;
                self.proceed_round(false)
            }
            ProtocolMessage(M::Round2(m)) => {
                let store = self
                    .msgs2
                    .as_mut()
                    .ok_or(KeygenError::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 2,
                    })?;

                let mut m_mut = m.clone();
                m_mut.sender = msg.sender as usize;
                m_mut.recipient = Address::Broadcast;
                if let Some(receiver) = msg.receiver {
                    m_mut.recipient = Address::Peer(receiver as usize);
                }
    
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m_mut,
                    })
                    .map_err(KeygenError::HandleMessage)?;
                self.proceed_round(false)
            }
            ProtocolMessage(M::Round3(m)) => {
                let store = self
                    .msgs3
                    .as_mut()
                    .ok_or(KeygenError::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 3,
                    })?;

                let mut m_mut = m.clone();
                m_mut.sender = msg.sender as usize;
                m_mut.recipient = Address::Broadcast;
                if let Some(receiver) = msg.receiver {
                    m_mut.recipient = Address::Peer(receiver as usize);
                }
    
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m_mut,
                    })
                    .map_err(KeygenError::HandleMessage)?;
                self.proceed_round(false)
            }
            ProtocolMessage(M::Round4(m)) => {
                let store = self
                    .msgs4
                    .as_mut()
                    .ok_or(KeygenError::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 4,
                    })?;

                let mut m_mut = m.clone();
                m_mut.sender = msg.sender as usize;
                m_mut.recipient = Address::Broadcast;
                if let Some(receiver) = msg.receiver {
                    m_mut.recipient = Address::Peer(receiver as usize);
                }
    
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m_mut,
                    })
                    .map_err(KeygenError::HandleMessage)?;
                self.proceed_round(false)
            }
        }
    }

    fn message_queue(&mut self) -> &mut Vec<Msg<ProtocolMessage>> {
        &mut self.msgs_queue
    }

    fn wants_to_proceed(&self) -> bool {
        let store1_wants_more = self.msgs1.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store2_wants_more = self.msgs2.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store3_wants_more = self.msgs3.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store4_wants_more = self.msgs4.as_ref().map(|s| s.wants_more()).unwrap_or(false);

        match &self.round {
            R::Round0(_) => true,
            R::Round1(_) => !store1_wants_more,
            R::Round2(_) => !store2_wants_more,
            R::Round3(_) => !store3_wants_more,
            R::Round4(_) => !store4_wants_more,
            R::Final(_) | R::Gone => false,
        }
    }

    fn proceed(&mut self) -> KeygenResult<()> {
        self.proceed_round(true)
    }

    fn round_timeout(&self) -> Option<Duration> {
        None
    }

    fn round_timeout_reached(&mut self) -> Self::Err {
        panic!("no timeout was set")
    }

    fn is_finished(&self) -> bool {
        matches!(self.round, R::Final(_))
    }

    fn pick_output(&mut self) -> Option<KeygenResult<LocalKey<Secp256k1>>> {
        match self.round {
            R::Final(_) => (),
            R::Gone => return Some(Err(KeygenError::DoublePickOutput)),
            _ => return None,
        }

        match replace(&mut self.round, R::Gone) {
            R::Final(result) => Some(Ok(result)),
            _ => unreachable!("guaranteed by match expression above"),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            R::Round0(_) => 0,
            R::Round1(_) => 1,
            R::Round2(_) => 2,
            R::Round3(_) => 3,
            R::Round4(_) => 4,
            R::Final(_) | R::Gone => 5,
        }
    }

    fn total_rounds(&self) -> Option<u16> {
        Some(4)
    }

    fn party_ind(&self) -> u16 {
        self.party_i
    }

    fn parties(&self) -> u16 {
        self.party_n
    }
}
