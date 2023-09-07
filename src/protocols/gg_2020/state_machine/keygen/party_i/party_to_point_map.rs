use std::collections::HashMap;
use curv::{BigInt, elliptic::curves::{ECScalar, Scalar, Secp256k1}, arithmetic::One};
use trace::trace;

use serde::{
    Serialize, 
    Deserialize
};

use crate::protocols::gg_2020::state_machine::keygen::types::FE;



#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyToPointMap {
    pub points: HashMap<usize, usize>,
}

impl PartyToPointMap {
    
    pub fn map_signing_parties_to_points(&self, signing_parties: &[usize]) -> Vec<usize> {
        let mut present = Vec::new();
        let mut absent = Vec::new();
        for idx in signing_parties {
            match self.points.get(idx) {
                Some(point) => present.push(*point),
                None => absent.push(*idx),
            }
        }

        assert_eq!(absent.len(), 0);

        present
    }

    pub fn calculate_lagrange_multiplier(&self, signing_parties: &[usize], own_x: FE) -> FE {
        // build set of points {1,2...}
        #[allow(clippy::cast_possible_truncation)]
        let subset_of_fe_points = self
            .map_signing_parties_to_points(signing_parties)
            .into_iter()
            .map(|x| {
                let index_bn = BigInt::from(x as u32);
                Scalar::<Secp256k1>::from_bigint(&index_bn)
            })
            .collect::<Vec<FE>>();

        let fold_with_one = |op: &dyn Fn(FE, &FE) -> FE| {
            subset_of_fe_points
                .iter()
                .filter(|x| (*x).as_raw() != own_x.as_raw())
                .fold(Scalar::<Secp256k1>::from_bigint(&BigInt::one()), |acc: FE, x| op(acc, x))
        };

        let num_fun = |acc: FE, x: &FE| acc * x;
        let denom_fun = |acc: FE, x: &FE| acc * FE::from_raw(x.as_raw().sub(&own_x.as_raw()));

        fold_with_one(&denom_fun).invert().unwrap() * fold_with_one(&num_fun)
    }
}