
use curv::elliptic::curves::Secp256k1;
use round_based::dev::Simulation;

use crate::protocols::gg_2020::state_machine::keygen::{
    local_key::LocalKey, 
    Keygen,
};

pub fn simulate_keygen(t: u16, n: u16) -> Vec<LocalKey<Secp256k1>> {
    let mut simulation = Simulation::new();
    simulation.enable_benchmarks(true);

    for i in 1..=n {
        simulation.add_party(Keygen::new(i, t, n).unwrap());
    }

    let keys = simulation.run().unwrap();

    println!("Benchmark results:");
    println!("{:#?}", simulation.benchmark_results().unwrap());

    keys
}

#[test]
fn simulate_keygen_t1_n2() {
    simulate_keygen(1, 2);
}

#[test]
fn simulate_keygen_t1_n3() {
    simulate_keygen(1, 3);
}

#[test]
fn simulate_keygen_t2_n3() {
    simulate_keygen(2, 3);
}