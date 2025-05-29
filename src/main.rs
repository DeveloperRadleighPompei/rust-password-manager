use argon2_kdf::{Hasher,Algorithm};
use rand::Rng;
use std::fs;
use std::io::{Read, Write};
fn setup(password: &[u8], salt_path: &str) {
    let hash = Hasher::new()
        .algorithm(Algorithm::Argon2id)
        .salt_length(16)
        .hash_length(32)
        .iterations(8)
        .memory_cost_kib(2*1024*1024)
        .threads(4)
        .hash(password)
        .unwrap();
    println!("{:?}", hash.salt_bytes());
    fs::write(salt_path, hash.salt_bytes()).expect("Failed to write salt");
}
fn main() {
    let password = b"hello";
    let salt_path = "salt.bin";
    setup(password, salt_path);
}