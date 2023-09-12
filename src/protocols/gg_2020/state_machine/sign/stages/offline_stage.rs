use std::convert::TryFrom;
use std::mem::replace;
use curv::elliptic::curves::secp256_k1::Secp256k1;
use round_based::containers::{BroadcastMsgs, MessageStore, P2PMsgs, Store};

use crate::{
    utilities::mta::MessageA,
    utilities::zk_pdl_with_slack::PDLwSlackProof,
    protocols::gg_2020::{
        party_i::{
            SignBroadcastPhase1, 
            SignDecommitPhase1, 
        },
        state_machine::{
            keygen::local_key::LocalKey,
            sign::{
                error::{
                    internal_error::InternalError,
                    sign_error::SignError,
                },
                types::SignResult,
                messages::{
                    GammaI,
                    WI,
                    RDash,
                    DeltaI,
                    TI,
                    TIProof,
                    SI,
                    HEGProof,
                    MsgQueue,
                },
                rounds::{
                    round_0::Round0,
                    round_1::Round1,
                    round_2::Round2,
                    round_3::Round3,
                    round_4::Round4,
                    round_5::Round5,
                    round_6::Round6, 
                    CompletedOfflineStage
                },
            },
        },
    },
};



#[allow(clippy::large_enum_variant)]
pub enum OfflineR {
    R0(Round0),
    R1(Round1),
    R2(Round2),
    R3(Round3),
    R4(Round4),
    R5(Round5),
    R6(Round6),
    Finished(CompletedOfflineStage),
    Gone,
}

pub struct OfflineStage {
    pub(crate) round: OfflineR,

    pub(crate) msgs1: Option<Store<BroadcastMsgs<(MessageA, SignBroadcastPhase1)>>>,
    pub(crate) msgs2: Option<Store<P2PMsgs<(GammaI, WI)>>>,
    pub(crate) msgs3: Option<Store<BroadcastMsgs<(DeltaI, TI, TIProof)>>>,
    pub(crate) msgs4: Option<Store<BroadcastMsgs<SignDecommitPhase1>>>,
    pub(crate) msgs5: Option<Store<BroadcastMsgs<(RDash, Vec<PDLwSlackProof>)>>>,
    pub(crate) msgs6: Option<Store<BroadcastMsgs<(SI, HEGProof)>>>,

    pub(crate) msgs_queue: MsgQueue,

    pub(crate) party_i: u16,
    pub(crate) party_n: u16,
}

impl OfflineStage {
    /// Construct a party of offline stage of threshold signing protocol
    ///
    /// Once offline stage is finished, parties can do one-round threshold signing (i.e. they only
    /// need to exchange a single set of messages).
    ///
    /// Takes party index `i` (in range `[1; n]`), list `s_l` of parties' indexes from keygen protocol
    /// (`s_l[i]` must be an index of party `i` that was used by this party in keygen protocol), and
    /// party local secret share `local_key`.
    ///
    /// Returns error if given arguments are contradicting.
    pub fn new(i: u16, s_l: Vec<u16>, local_key: LocalKey<Secp256k1>) -> SignResult<Self> {
        if s_l.len() < 2 {
            return Err(SignError::TooFewParties);
        }
        if i == 0 || usize::from(i) > s_l.len() {
            return Err(SignError::InvalidPartyIndex);
        }

        let keygen_n = local_key.key_params.share_count;
        if s_l.iter().any(|&i| i == 0 || i > keygen_n) {
            return Err(SignError::InvalidSl);
        }
        {
            // Check if s_l has duplicates
            let mut s_l_sorted = s_l.clone();
            s_l_sorted.sort_unstable();
            let mut s_l_sorted_deduped = s_l_sorted.clone();
            s_l_sorted_deduped.dedup();

            if s_l_sorted != s_l_sorted_deduped {
                return Err(SignError::InvalidSl);
            }
        }

        let n = u16::try_from(s_l.len()).map_err(|_| SignError::TooManyParties { n: s_l.len() })?;

        Ok(Self {
            round: OfflineR::R0(Round0 { i, s_l, local_key }),

            msgs1: Some(Round1::expects_messages(i, n)),
            msgs2: Some(Round2::expects_messages(i, n)),
            msgs3: Some(Round3::expects_messages(i, n)),
            msgs4: Some(Round4::expects_messages(i, n)),
            msgs5: Some(Round5::expects_messages(i, n)),
            msgs6: Some(Round6::expects_messages(i, n)),

            msgs_queue: MsgQueue(vec![]),

            party_i: i,
            party_n: n,
        })
    }

    // fn proceed_state(&mut self, may_block: bool) -> Result<()> {
    //     self.proceed_round(may_block)?;
    //     self.proceed_decommit_round(may_block)
    // }

    pub(crate) fn proceed_round(&mut self, may_block: bool) -> SignResult<()> {
        let store1_wants_more = self.msgs1.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store2_wants_more = self.msgs2.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store3_wants_more = self.msgs3.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store4_wants_more = self.msgs4.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store5_wants_more = self.msgs5.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store6_wants_more = self.msgs6.as_ref().map(|s| s.wants_more()).unwrap_or(false);

        let next_state: OfflineR;
        let try_again: bool = match replace(&mut self.round, OfflineR::Gone) {
            OfflineR::R0(round) if !round.is_expensive() || may_block => {
                next_state = round
                    .proceed(&mut self.msgs_queue)
                    .map(OfflineR::R1)
                    .map_err(SignError::ProceedRound)?;
                true
            }
            s @ OfflineR::R0(_) => {
                next_state = s;
                false
            }
            OfflineR::R1(round) if !store1_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs1.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs, &mut self.msgs_queue)
                    .map(OfflineR::R2)
                    .map_err(SignError::ProceedRound)?;
                true
            }
            s @ OfflineR::R1(_) => {
                next_state = s;
                false
            }
            OfflineR::R2(round) if !store2_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs2.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs, &mut self.msgs_queue)
                    .map(OfflineR::R3)
                    .map_err(SignError::ProceedRound)?;
                true
            }
            s @ OfflineR::R2(_) => {
                next_state = s;
                false
            }
            OfflineR::R3(round) if !store3_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs3.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs, &mut self.msgs_queue)
                    .map(OfflineR::R4)
                    .map_err(SignError::ProceedRound)?;
                true
            }
            s @ OfflineR::R3(_) => {
                next_state = s;
                false
            }
            OfflineR::R4(round) if !store4_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs4.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs, &mut self.msgs_queue)
                    .map(OfflineR::R5)
                    .map_err(SignError::ProceedRound)?;
                false
            }
            s @ OfflineR::R4(_) => {
                next_state = s;
                false
            }
            OfflineR::R5(round) if !store5_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs5.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs, &mut self.msgs_queue)
                    .map(OfflineR::R6)
                    .map_err(SignError::ProceedRound)?;
                false
            }
            s @ OfflineR::R5(_) => {
                next_state = s;
                false
            }
            OfflineR::R6(round) if !store6_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs6.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs)
                    .map(OfflineR::Finished)
                    .map_err(SignError::ProceedRound)?;
                false
            }
            s @ OfflineR::R6(_) => {
                next_state = s;
                false
            }
            s @ OfflineR::Finished(_) | s @ OfflineR::Gone => {
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
