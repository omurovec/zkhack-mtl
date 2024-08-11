extern crate num_bigint as bigint;

use bigint::BigUint;
use bincode;
use chrono::{Datelike, Local, Timelike};
use hex;
use methods::{MOD_EXP_IN_RANGE_ELF, MOD_EXP_IN_RANGE_ID};
use risc0_zkvm::serde::to_vec;
use risc0_zkvm::{default_prover, ExecutorEnv};
use serde_json::json;
use std::fs::{self, File};
use std::path::Path;

fn main() {
    let base: BigUint = BigUint::parse_bytes(b"4", 10).unwrap();
    let modulus: BigUint = BigUint::parse_bytes(
        b"00a09ecd8ada2a30634181e1bf5452b92268d2373ad4b234c750b79cb09cb2c82f2fd51310d7a771f44ccf58b46d94c156107c0695d289adb58280d8479da80b4f",
        16,
    )
    .unwrap();
    let range: BigUint = modulus.clone() / BigUint::parse_bytes(b"5000000", 10).unwrap();
    println!("range: {:?}", range.to_str_radix(16));
    let exp: BigUint = BigUint::parse_bytes(b"b7c8d9", 16).unwrap();

    println!(
        "Sending values to guest: base = {}, modulus = {}, range = {}, exp = {}",
        base, modulus, range, exp
    );

    let env = create_execution_env(base, modulus, range, exp);
    let receipt = run_prover(env);
    let serialized_data = extract_serialized_data(&receipt);
    let output_filename = generate_timestamped_filename();

    save_to_json(&output_filename, &serialized_data);
    decode_and_display_output(&receipt);
}

fn create_execution_env(
    base: BigUint,
    modulus: BigUint,
    range: BigUint,
    exp: BigUint,
) -> ExecutorEnv<'static> {
    ExecutorEnv::builder()
        .write(&to_vec(&base.clone()).unwrap())
        .unwrap() // base
        .write(&to_vec(&modulus.clone()).unwrap())
        .unwrap() // modulus
        .write(&to_vec(&range.clone()).unwrap())
        .unwrap() // range
        .write(&to_vec(&exp.clone()).unwrap())
        .unwrap() // exp
        .build()
        .unwrap()
}

fn run_prover(env: ExecutorEnv) -> risc0_zkvm::Receipt {
    let prover = default_prover();
    println!("Proving...");
    let receipt = prover.prove(env, MOD_EXP_IN_RANGE_ELF).unwrap().receipt;
    println!("Receipt received...");
    receipt
}

fn extract_serialized_data(receipt: &risc0_zkvm::Receipt) -> serde_json::Value {
    let receipt_inner_bytes_array = bincode::serialize(&receipt.inner).unwrap();
    let receipt_journal_bytes_array = bincode::serialize(&receipt.journal).unwrap();

    let image_id_hex: String = MOD_EXP_IN_RANGE_ID
        .iter()
        .map(|&value| format!("{:08x}", value.to_be()))
        .collect();

    json!({
        "proof": format!("0x{}", hex::encode(receipt_inner_bytes_array)),
        "outputs": format!("0x{}", hex::encode(receipt_journal_bytes_array)),
        "image_id": format!("0x{}", image_id_hex)
    })
}

fn generate_timestamped_filename() -> String {
    let now = Local::now();
    format!(
        "proof_{}-{:02}-{:02}_{:02}-{:02}-{:02}-{:03}.json",
        now.year(),
        now.month(),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.timestamp_subsec_millis()
    )
}

fn save_to_json(filename: &str, data: &serde_json::Value) {
    let dir = Path::new("data");
    if !dir.exists() {
        fs::create_dir_all(dir).expect("Failed to create data directory");
    }

    let filepath = dir.join(filename);

    let mut file = File::create(&filepath).expect("Failed to create file");
    serde_json::to_writer_pretty(&mut file, data).expect("Failed to serialize data to JSON");
    println!("Data saved to {:?}", filepath);
}

fn decode_and_display_output(receipt: &risc0_zkvm::Receipt) {
    let output: u128 = receipt.journal.decode().unwrap();
    println!(
        "Hello, world! I generated a proof of guest execution! {} is a public output from the journal",
        output
    );
}
