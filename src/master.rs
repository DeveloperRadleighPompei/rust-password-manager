use argon2_kdf::{Algorithm, Hasher};
use aes_gcm::Key;
use aes_gcm::Aes256Gcm;
use std::fs;
use std::path::Path;

pub fn create_master(password: &[u8], salt_path: &str) {
    let hash = Hasher::new()
        .algorithm(Algorithm::Argon2id)
        .salt_length(16)
        .hash_length(32)
        .iterations(8)
        .memory_cost_kib(2 * 1024 * 1024)
        .threads(4)
        .hash(password)
        .unwrap();
    fs::write(salt_path, hash.salt_bytes()).expect("Failed to write salt");
}

pub fn key_from_master_and_salt(password: &[u8], salt_path: &str) -> Key<Aes256Gcm> {
    let salt = fs::read(salt_path).expect("Failed to read salt");
    let hash = Hasher::new()
        .algorithm(Algorithm::Argon2id)
        .custom_salt(&salt)
        .hash_length(32)
        .iterations(8)
        .memory_cost_kib(2 * 1024 * 1024)
        .threads(4)
        .hash(password)
        .unwrap();
    let bytes = hash.as_bytes();
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(bytes);
    Key::<Aes256Gcm>::from_slice(&key_bytes).clone()
}
pub fn login(password: &[u8], salt_path: &str, vault_path: &str) -> Option<Vec<u8>> {
    if Path::new(vault_path).exists() {
        match crate::vault::decrypt_vault(password, salt_path, vault_path) {
            Ok(_) => Some(password.to_vec()),
            Err(e) => {
                println!("Login failed: {}", e);
                None
            }
        }
    } else {
        println!("No vault found. Creating new one.");
        create_master(password, salt_path);
        Some(password.to_vec())
    }
}
