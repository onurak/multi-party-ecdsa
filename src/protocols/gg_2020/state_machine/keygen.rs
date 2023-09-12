pub mod rounds;
pub mod party_i;
pub mod messages;
pub mod local_key;
pub mod trait_impls;
pub mod error;
pub mod types;
#[cfg(test)]
pub mod test;

use std::{mem::replace, collections::BTreeSet};
use round_based::{
    Msg,
    containers::{
        push::{Push, PushExt},
        *,
    },
};

use crate::protocols::gg_2020::state_machine::keygen::{
    error::{
        internal_error::InternalError,
        keygen_error::KeygenError,
    },
    messages::{
        ProtocolMessage,
        broadcast::KeyGenBroadcast,
        decommit::KeyGenDecommit,
        feldman_vss::FeldmanVSS,
        M,
        parameters::Parameters,
        proof::Proof,
    },
    types::KeygenResult,
    rounds::{
        R,
        round_0::Round0, 
        round_1::Round1, 
        round_2::Round2, 
        round_3::Round3, 
        round_4::Round4
    },
};

pub struct Keygen {
    round: R,

    msgs1: Option<Store<BroadcastMsgs<KeyGenBroadcast>>>,
    msgs2: Option<Store<BroadcastMsgs<KeyGenDecommit>>>,
    msgs3: Option<Store<P2PMsgs<FeldmanVSS>>>,
    msgs4: Option<Store<BroadcastMsgs<Proof>>>,

    msgs_queue: Vec<Msg<ProtocolMessage>>,

    party_i: u16,
    party_n: u16,
}

impl Keygen {
    /// Constructs a party of keygen protocol
    ///
    /// Takes party index `i` (in range `[1; n]`), threshold value `t`, and total number of
    /// parties `n`. Party index identifies this party in the protocol, so it must be guaranteed
    /// to be unique.
    ///
    /// Returns error if:
    /// * `n` is less than 2, returns [Error::TooFewParties]
    /// * `t` is not in range `[1; n-1]`, returns [Error::InvalidThreshold]
    /// * `i` is not in range `[1; n]`, returns [Error::InvalidPartyIndex]
    pub fn new(i: u16, t: u16, n: u16) -> KeygenResult<Self> {
        if n < 2 {
            return Err(KeygenError::TooFewParties);
        }
        if t == 0 || t >= n {
            return Err(KeygenError::InvalidThreshold);
        }
        if i == 0 || i > n {
            return Err(KeygenError::InvalidPartyIndex);
        }


        let other_parties: BTreeSet<usize> = (1..=(n as usize)).into_iter().filter(|x| *x != i as usize).collect();

        let mut state = Self {
            round: R::Round0(Round0 { 
                own_party_index: i as usize, 
                key_params: Parameters::new(t, n),
                other_parties
            }),

            msgs1: Some(Round1::expects_messages(i, n)),
            msgs2: Some(Round2::expects_messages(i, n)),
            msgs3: Some(Round3::expects_messages(i, n)),
            msgs4: Some(Round4::expects_messages(i, n)),

            msgs_queue: vec![],

            party_i: i,
            party_n: n,
        };

        state.proceed_round(false)?;
        Ok(state)
    }

    fn gmap_queue<'a, T, F>(&'a mut self, mut f: F) -> impl Push<Msg<T>> + 'a
    where
        F: FnMut(T) -> M + 'a,
    {
        (&mut self.msgs_queue).gmap(move |m: Msg<T>| m.map_body(|m| ProtocolMessage(f(m))))
    }

    /// Proceeds round state if it received enough messages and if it's cheap to compute or
    /// `may_block == true`
    fn proceed_round(&mut self, may_block: bool) -> KeygenResult<()> {
        let store1_wants_more = self.msgs1.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store2_wants_more = self.msgs2.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store3_wants_more = self.msgs3.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store4_wants_more = self.msgs4.as_ref().map(|s| s.wants_more()).unwrap_or(false);

        let next_state: R;
        let try_again: bool = match replace(&mut self.round, R::Gone) {
            R::Round0(round) if !round.is_expensive() || may_block => {
                next_state = round
                    .proceed(self.gmap_queue(M::Round1))
                    .map(R::Round1)
                    .map_err(KeygenError::ProceedRound)?;
                true
            }
            s @ R::Round0(_) => {
                next_state = s;
                false
            }
            R::Round1(round) if !store1_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs1.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveRoundMessages)?;
                next_state = round
                    .proceed(msgs, self.gmap_queue(M::Round2))
                    .map(R::Round2)
                    .map_err(KeygenError::ProceedRound)?;
                true
            }
            s @ R::Round1(_) => {
                next_state = s;
                false
            }
            R::Round2(round) if !store2_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs2.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveRoundMessages)?;
                next_state = round
                    .proceed(msgs, self.gmap_queue(M::Round3))
                    .map(R::Round3)
                    .map_err(KeygenError::ProceedRound)?;
                true
            }
            s @ R::Round2(_) => {
                next_state = s;
                false
            }
            R::Round3(round) if !store3_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs3.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveRoundMessages)?;
                next_state = round
                    .proceed(msgs, self.gmap_queue(M::Round4))
                    .map(R::Round4)
                    .map_err(KeygenError::ProceedRound)?;
                true
            }
            s @ R::Round3(_) => {
                next_state = s;
                false
            }
            R::Round4(round) if !store4_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs4.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveRoundMessages)?;
                next_state = round
                    .proceed(msgs)
                    .map(R::Final)
                    .map_err(KeygenError::ProceedRound)?;
                true
            }
            s @ R::Round4(_) => {
                next_state = s;
                false
            }
            s @ R::Final(_) | s @ R::Gone => {
                next_state = s;
                false
            }
        };

        self.round = next_state;
        if try_again {
            self.proceed_round(may_block)
        } else {
            Ok(())
        }
    }
}

