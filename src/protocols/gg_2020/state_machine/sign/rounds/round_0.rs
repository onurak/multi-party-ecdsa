use curv::elliptic::curves::secp256_k1::Secp256k1;
use round_based::{
    Msg,
    containers::push::Push,
};

use crate::{
    utilities::mta::MessageA, 
    protocols::gg_2020::party_i::SignBroadcastPhase1,
    protocols::gg_2020::{
        party_i::SignKeys,
        state_machine::keygen::local_key::LocalKey,
        state_machine::sign::{
            rounds::round_1::Round1,
            types::SignRoundResult,
        }, 
        
    }
};

pub struct Round0 {
    /// Index of this party
    ///
    /// Must be in range `[0; n)` where `n` is number of parties involved in signing.
    pub i: u16,

    /// List of parties' indexes from keygen protocol
    ///
    /// I.e. `s_l[i]` must be an index of party `i` that was used by this party in keygen protocol.
    // s_l.len()` equals to `n` (number of parties involved in signing)
    pub s_l: Vec<u16>,

    /// Party local secret share
    pub local_key: LocalKey<Secp256k1>,
}

impl Round0 {
    pub fn proceed<O>(self, mut output: O) -> SignRoundResult<Round1>
    where
        O: Push<Msg<(MessageA, SignBroadcastPhase1)>>,
    {
        let sign_keys = SignKeys::create(
            &self.local_key.keys_linear.x_i,
            &self.local_key.vss_scheme.clone(),
            usize::from(self.s_l[usize::from(self.i - 1)]) - 1,
            &self
                .s_l
                .iter()
                .map(|&i| usize::from(i) - 1)
                .collect::<Vec<_>>(),
        );
        let (bc1, decom1) = sign_keys.phase1_broadcast();

        let party_ek = self.local_key.paillier_key_vec[usize::from(self.local_key.own_party_index - 1)].clone();
        let m_a = MessageA::a(&sign_keys.k_i, &party_ek, &self.local_key.h1_h2_n_tilde_vec);

        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: (m_a.0.clone(), bc1.clone()),
        });

        let round1 = Round1 {
            i: self.i,
            s_l: self.s_l.clone(),
            local_key: self.local_key,
            m_a,
            sign_keys,
            phase1_com: bc1,
            phase1_decom: decom1,
        };

        Ok(round1)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}