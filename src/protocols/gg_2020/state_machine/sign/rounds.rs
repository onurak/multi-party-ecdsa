#![allow(non_snake_case)]

pub mod round_0;
pub mod round_1;
pub mod round_2;
pub mod round_3;
pub mod round_4;
pub mod round_5;
pub mod round_6;
pub mod round_7;

use serde::{Deserialize, Serialize};
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use sha2::Sha256;

use crate::utilities::mta::MessageB;
use curv::cryptographic_primitives::proofs::{
    sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof,
    sigma_valid_pedersen::PedersenProof,
};

use crate::protocols::gg_2020::{
    party_i::SignKeys,
    state_machine::keygen::local_key::LocalKey,
};



// #[derive(Serialize, Deserialize, Debug, Clone)]
// #[allow(clippy::upper_case_acronyms)]
// pub struct GWI(pub Point<Secp256k1>);




#[derive(Clone)]
pub struct CompletedOfflineStage {
    i: u16,
    local_key: LocalKey<Secp256k1>,
    sign_keys: SignKeys,
    t_vec: Vec<Point<Secp256k1>>,
    R: Point<Secp256k1>,
    sigma_i: Scalar<Secp256k1>,
}

impl CompletedOfflineStage {
    pub fn public_key(&self) -> &Point<Secp256k1> {
        &self.local_key.public_key
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PartialSignature(Scalar<Secp256k1>);


trait IteratorExt: Iterator {
    fn unzip3<A, B, C>(self) -> (Vec<A>, Vec<B>, Vec<C>)
    where
        Self: Iterator<Item = (A, B, C)> + Sized,
    {
        let (mut a, mut b, mut c) = (vec![], vec![], vec![]);
        for (a_i, b_i, c_i) in self {
            a.push(a_i);
            b.push(b_i);
            c.push(c_i);
        }
        (a, b, c)
    }
}

impl<I> IteratorExt for I where I: Iterator {}
