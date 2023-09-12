
use curv::BigInt;
use curv::arithmetic::Converter;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::Secp256k1;
use round_based::dev::Simulation;
use sha2::Sha256;

use crate::protocols::gg_2020::{
    state_machine::keygen::local_key::LocalKey,
    party_i::verify,
    state_machine::keygen::test::simulate_keygen,
    state_machine::sign::{
        rounds::CompletedOfflineStage,
        stages::offline_stage::OfflineStage,
        stages::sign_manual::SignManual,
    }
};

fn simulate_offline_stage(
    local_keys: Vec<LocalKey<Secp256k1>>,
    s_l: &[u16],
) -> Vec<CompletedOfflineStage> {
    let mut simulation = Simulation::new();
    simulation.enable_benchmarks(true);

    for (i, &keygen_i) in (1..).zip(s_l) {
        simulation.add_party(
            OfflineStage::new(
                i,
                s_l.to_vec(),
                local_keys[usize::from(keygen_i - 1)].clone(),
            )
            .unwrap(),
        );
    }

    let stages = simulation.run().unwrap();

    println!("Benchmark results:");
    println!("{:#?}", simulation.benchmark_results().unwrap());

    stages
}

fn simulate_signing(offline: Vec<CompletedOfflineStage>, message: &[u8]) {
    let message = Sha256::new()
        .chain_bigint(&BigInt::from_bytes(message))
        .result_bigint();
    let pk = offline[0].public_key().clone();

    let parties = offline
        .iter()
        .map(|o| SignManual::new(message.clone(), o.clone()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let (parties, local_sigs): (Vec<_>, Vec<_>) = parties.into_iter().unzip();
    // parties.remove(0).complete(&local_sigs[1..]).unwrap();
    let local_sigs_except = |i: usize| {
        let mut v = vec![];
        v.extend_from_slice(&local_sigs[..i]);
        if i + 1 < local_sigs.len() {
            v.extend_from_slice(&local_sigs[i + 1..]);
        }
        v
    };

    assert!(parties
        .into_iter()
        .enumerate()
        .map(|(i, p)| p.complete(&local_sigs_except(i)).unwrap())
        .all(|signature| verify(&signature, &pk, &message).is_ok()));
}

#[test]
fn simulate_offline_stage_t1_n2_s2() {
    let local_keys = simulate_keygen(1, 2);
    simulate_offline_stage(local_keys, &[1, 2]);
}

#[test]
fn simulate_offline_stage_t1_n3_s2() {
    let local_keys = simulate_keygen(1, 3);
    simulate_offline_stage(local_keys, &[1, 3]);
}

#[test]
fn simulate_offline_stage_t2_n3_s3() {
    let local_keys = simulate_keygen(2, 3);
    simulate_offline_stage(local_keys, &[1, 2, 3]);
}

#[test]
fn simulate_signing_t1_n2_s2() {
    let local_keys = simulate_keygen(1, 2);
    let offline_stage = simulate_offline_stage(local_keys, &[1, 2]);
    simulate_signing(offline_stage, b"ZenGo")
}

#[test]
fn simulate_signing_t1_n3_s2() {
    let local_keys = simulate_keygen(1, 3);
    let offline_stage = simulate_offline_stage(local_keys.clone(), &[1, 2]);
    simulate_signing(offline_stage, b"ZenGo");
    let offline_stage = simulate_offline_stage(local_keys.clone(), &[1, 3]);
    simulate_signing(offline_stage, b"ZenGo");
    let offline_stage = simulate_offline_stage(local_keys, &[2, 3]);
    simulate_signing(offline_stage, b"ZenGo");
}

#[test]
fn simulate_signing_t2_n3_s3() {
    let local_keys = simulate_keygen(2, 3);
    let offline_stage = simulate_offline_stage(local_keys, &[1, 2, 3]);
    simulate_signing(offline_stage, b"ZenGo")
}
