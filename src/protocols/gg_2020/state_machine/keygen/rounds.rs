pub mod round_0;
pub mod round_1;
pub mod round_2;
pub mod round_3;
pub mod round_4;

use curv::elliptic::curves::Secp256k1;
use crate::protocols::gg_2020::state_machine::keygen::local_key::LocalKey;

pub enum R {
    Round0(round_0::Round0),
    Round1(round_1::Round1),
    Round2(round_2::Round2),
    Round3(round_3::Round3),
    Round4(round_4::Round4),
    Final(LocalKey<Secp256k1>),
    Gone,
}

