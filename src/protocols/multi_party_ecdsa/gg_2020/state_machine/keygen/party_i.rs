pub mod keys;
pub mod shared_keys;

use curv::arithmetic::traits::*;
use curv::BigInt;
use paillier::{
    KeyGeneration, Paillier, 
};

pub fn generate_h1_h2_n_tilde() -> (BigInt, BigInt, BigInt, BigInt, BigInt) {

    let (ek_tilde, dk_tilde) = Paillier::keypair_safe_primes().keys();
    let one = BigInt::one();
    let phi = (&dk_tilde.p - &one) * (&dk_tilde.q - &one);
    let h1 = BigInt::sample_below(&ek_tilde.n);
    let (mut xhi, mut xhi_inv) = loop {
        let xhi_ = BigInt::sample_below(&phi);
        match BigInt::mod_inv(&xhi_, &phi) {
            Some(inv) => break (xhi_, inv),
            None => continue,
        }
    };
    let h2 = BigInt::mod_pow(&h1, &xhi, &ek_tilde.n);
    xhi = BigInt::sub(&phi, &xhi);
    xhi_inv = BigInt::sub(&phi, &xhi_inv);

    (ek_tilde.n, h1, h2, xhi, xhi_inv)
}

