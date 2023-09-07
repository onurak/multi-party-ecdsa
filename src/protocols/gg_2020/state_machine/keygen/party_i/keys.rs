use std::fmt::Debug;

use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Curve, Point, Scalar};
use curv::BigInt;
use sha2::Sha256;

use crate::protocols::gg_2020::state_machine::keygen::{
    messages::broadcast::KeyGenBroadcast,
    messages::decommit::KeyGenDecommit,
    messages::feldman_vss::FeldmanVSS,
    messages::parameters::Parameters,
    messages::proof::Proof,
    messages::address::Address,
    party_i::shared_keys::SharedKeys,
    party_i::paillier_keys::PaillierKeys,
};


use paillier::{
    KeyGeneration, 
    Paillier, 
};

use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::NiCorrectKeyProof;
use zk_paillier::zkproofs::{CompositeDLogProof, DLogStatement};

use crate::protocols::gg_2020::ErrorType;
use std::convert::TryInto;


const SECURITY: usize = 256;
const PAILLIER_MIN_BIT_LENGTH: usize = 2047;
const PAILLIER_MAX_BIT_LENGTH: usize = 2048;


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Keys<E: Curve = Secp256k1> {
    
    pub u_i: Scalar<E>,
    pub y_i: Point<E>,
    pub paillier_keys: PaillierKeys,

    pub party_index: usize,
    pub n_tilde: BigInt,
    pub h1: BigInt,
    pub h2: BigInt,
    pub xhi: BigInt,
    pub xhi_inv: BigInt,
}

impl Keys {

    pub fn create_safe_prime(index: usize) -> Self {
        let u = Scalar::<Secp256k1>::random();
        let y = Point::generator() * &u;

        let (ek, dk) = Paillier::keypair_safe_primes().keys();
        let (n_tilde, h1, h2, xhi, xhi_inv) = super::generate_h1_h2_n_tilde();

        Self {
            u_i: u,
            y_i: y,
            paillier_keys: PaillierKeys::new(dk, ek),
            party_index: index,
            n_tilde,
            h1,
            h2,
            xhi,
            xhi_inv,
        }
    }

    pub fn phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2(
        &self,
    ) -> (KeyGenBroadcast, KeyGenDecommit) {
        let blind_factor = BigInt::sample(SECURITY);
        let correct_key_proof = NiCorrectKeyProof::proof(&self.paillier_keys.dk, None);

        let dlog_statement_base_h1 = DLogStatement {
            N: self.n_tilde.clone(),
            g: self.h1.clone(),
            ni: self.h2.clone(),
        };
        let dlog_statement_base_h2 = DLogStatement {
            N: self.n_tilde.clone(),
            g: self.h2.clone(),
            ni: self.h1.clone(),
        };

        let composite_dlog_proof_base_h1 =
            CompositeDLogProof::prove(&dlog_statement_base_h1, &self.xhi);
        let composite_dlog_proof_base_h2 =
            CompositeDLogProof::prove(&dlog_statement_base_h2, &self.xhi_inv);

        let com = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(self.y_i.to_bytes(true).as_ref()),
            &blind_factor,
        );
        let bcm1 = KeyGenBroadcast {
            e: self.paillier_keys.ek.clone(),
            dlog_statement: dlog_statement_base_h1,
            com,
            correct_key_proof,
            composite_dlog_proof_base_h1,
            composite_dlog_proof_base_h2,
            
            sender: self.party_index,
            recipient: Address::Broadcast,
        };
        let decom1 = KeyGenDecommit {
            blind_factor,
            y_i: self.y_i.clone(),
            
            sender: self.party_index,
            recipient: Address::Broadcast,
        };
        (bcm1, decom1)
    }

    pub fn phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute(
        &self,
        params: &Parameters,
        decom_vec: &[KeyGenDecommit],
        bc1_vec: &[KeyGenBroadcast],
    ) -> Result<(VerifiableSS<Secp256k1>, Vec<Scalar<Secp256k1>>, usize), ErrorType> {
        let mut bad_actors_vec = Vec::new();
        // test length:
        assert_eq!(decom_vec.len(), usize::from(params.share_count));
        assert_eq!(bc1_vec.len(), usize::from(params.share_count));
        // test paillier correct key, h1,h2 correct generation and test decommitments
        let correct_key_correct_decom_all = (0..bc1_vec.len())
            .map(|i| {
                let dlog_statement_base_h2 = DLogStatement {
                    N: bc1_vec[i].dlog_statement.N.clone(),
                    g: bc1_vec[i].dlog_statement.ni.clone(),
                    ni: bc1_vec[i].dlog_statement.g.clone(),
                };
                let test_res =
                    HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                        &BigInt::from_bytes(&decom_vec[i].y_i.to_bytes(true)),
                        &decom_vec[i].blind_factor,
                    ) == bc1_vec[i].com
                        && bc1_vec[i]
                            .correct_key_proof
                            .verify(&bc1_vec[i].e, zk_paillier::zkproofs::SALT_STRING)
                            .is_ok()
                        && bc1_vec[i].e.n.bit_length() >= PAILLIER_MIN_BIT_LENGTH
                        && bc1_vec[i].e.n.bit_length() <= PAILLIER_MAX_BIT_LENGTH
                        && bc1_vec[i].dlog_statement.N.bit_length() >= PAILLIER_MIN_BIT_LENGTH
                        && bc1_vec[i].dlog_statement.N.bit_length() <= PAILLIER_MAX_BIT_LENGTH
                        && bc1_vec[i]
                            .composite_dlog_proof_base_h1
                            .verify(&bc1_vec[i].dlog_statement)
                            .is_ok()
                        && bc1_vec[i]
                            .composite_dlog_proof_base_h2
                            .verify(&dlog_statement_base_h2)
                            .is_ok();
                if !test_res {
                    bad_actors_vec.push(i);
                    false
                } else {
                    true
                }
            })
            .all(|x| x);

        let err_type = ErrorType {
            error_type: "invalid key".to_string(),
            bad_actors: bad_actors_vec,
        };

        let (vss_scheme, secret_shares) =
            VerifiableSS::share(params.threshold, params.share_count, &self.u_i);
        if correct_key_correct_decom_all {
            Ok((vss_scheme, secret_shares.to_vec(), self.party_index))
        } else {
            Err(err_type)
        }
    }

    pub fn phase2_verify_vss_construct_keypair_phase3_pok_dlog(
        &self,
        params: &Parameters,
        y_vec: &[Point<Secp256k1>],
        // secret_shares_vec: &[Scalar<Secp256k1>],
        // vss_scheme_vec: &[VerifiableSS<Secp256k1>],
        feldman_vss_vec: &Vec<FeldmanVSS>,
        index: usize,
    ) -> Result<(SharedKeys, Proof), ErrorType> {
        let mut bad_actors_vec = Vec::new();
        assert_eq!(y_vec.len(), usize::from(params.share_count));
        assert_eq!(feldman_vss_vec.len(), usize::from(params.share_count));
        // assert_eq!(vss_scheme_vec.len(), usize::from(params.share_count));

        let correct_ss_verify = (0..y_vec.len())
            .map(|i| {
                let res = feldman_vss_vec[i].vss
                    .validate_share(&feldman_vss_vec[i].share.1, index.try_into().unwrap())
                    .is_ok()
                    && feldman_vss_vec[i].vss.commitments[0] == y_vec[i];
                if !res {
                    bad_actors_vec.push(i);
                    false
                } else {
                    true
                }
            })
            .all(|x| x);

        let err_type = ErrorType {
            error_type: "invalid vss".to_string(),
            bad_actors: bad_actors_vec,
        };

        if correct_ss_verify {
            let (head, tail) = y_vec.split_at(1);
            let y = tail.iter().fold(head[0].clone(), |acc, x| acc + x);

            let x_i = feldman_vss_vec
                .iter()
                .fold(Scalar::<Secp256k1>::zero(), |acc, x| acc + x.share.1.clone());
            let dlog_proof = DLogProof::prove(&x_i);
            let proof = Proof { 
                proof: dlog_proof,
                sender: self.party_index,
                recipient: Address::Broadcast
            };
            Ok((SharedKeys { y, x_i }, proof))
        } else {
            Err(err_type)
        }
    }

    pub fn get_commitments_to_xi(
        vss_scheme_vec: &[VerifiableSS<Secp256k1>],
    ) -> Vec<Point<Secp256k1>> {
        let len = vss_scheme_vec.len();
        let (head, tail) = vss_scheme_vec.split_at(1);
        let mut global_coefficients = head[0].commitments.clone();
        for vss in tail {
            for (i, coefficient_commitment) in vss.commitments.iter().enumerate() {
                global_coefficients[i] = &global_coefficients[i] + coefficient_commitment;
            }
        }

        let global_vss = VerifiableSS {
            parameters: vss_scheme_vec[0].parameters.clone(),
            commitments: global_coefficients,
        };
        (1..=len)
            .map(|i| global_vss.get_point_commitment(i.try_into().unwrap()))
            .collect::<Vec<Point<Secp256k1>>>()
    }

    pub fn update_commitments_to_xi(
        comm: &Point<Secp256k1>,
        vss_scheme: &VerifiableSS<Secp256k1>,
        index: usize,
        s: &[usize],
    ) -> Point<Secp256k1> {
        let s: Vec<u16> = s.iter().map(|&i| i.try_into().unwrap()).collect();
        let li = VerifiableSS::<Secp256k1>::map_share_to_new_params(
            &vss_scheme.parameters,
            index.try_into().unwrap(),
            s.as_slice(),
        );
        comm * &li
    }

    pub fn verify_dlog_proofs_check_against_vss(
        params: &Parameters,
        dlog_proofs_vec: &[Proof],
        y_vec: &[Point<Secp256k1>],
        vss_vec: &[VerifiableSS<Secp256k1>],
    ) -> Result<(), ErrorType> {
        let mut bad_actors_vec = Vec::new();
        assert_eq!(y_vec.len(), usize::from(params.share_count));
        assert_eq!(dlog_proofs_vec.len(), usize::from(params.share_count));
        let xi_commitments = Keys::get_commitments_to_xi(vss_vec);
        let xi_dlog_verify = (0..y_vec.len())
            .map(|i| {
                let ver_res = DLogProof::verify(&dlog_proofs_vec[i].proof).is_ok();
                let verify_against_vss = xi_commitments[i] == dlog_proofs_vec[i].proof.pk;
                if !ver_res || !verify_against_vss {
                    bad_actors_vec.push(i);
                    false
                } else {
                    true
                }
            })
            .all(|x| x);

        let err_type = ErrorType {
            error_type: "bad dlog proof".to_string(),
            bad_actors: bad_actors_vec,
        };

        if xi_dlog_verify {
            Ok(())
        } else {
            Err(err_type)
        }
    }
}
