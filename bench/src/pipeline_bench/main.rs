#![allow(clippy::cast_precision_loss)]

mod bench_args;
mod block_builder;
mod chain_generator;
mod chain_spec;
mod coin_pool;
mod cpu_meter;
mod keyring;
mod replay_driver;
mod seeded_storage;
mod spendable_coin;
mod synthetic_chain;
mod tx_signer;

use std::process::ExitCode;

use bench_args::BenchArgs;
use replay_driver::ReplayDriver;

fn main() -> ExitCode {
    match BenchArgs::parse(std::env::args().skip(1)).and_then(|args| ReplayDriver::run(&args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
