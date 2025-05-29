use argon2_kdf::{Hasher, Algorithm};
use std::fs::{self, File};
use std::io::Write;
use serde::{Deserialize, Serialize};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key,
};

#[derive(Serialize, Deserialize, Debug)]
struct PasswordEntry {
    name: String,
    username: String,
    password: String,
    notes: Option<String>,
}

fn create_master(password: &[u8], salt_path: &str) {
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

fn key_from_master_and_salt(password: &[u8], salt_path: &str) -> Key<Aes256Gcm> {
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

fn build_vault(name: String, username: String, password: String, notes: Option<String>) -> Vec<PasswordEntry> {
    vec![PasswordEntry {
        name,
        username,
        password,
        notes,
    }]
}

fn encrypt_and_save_vault(password: &[u8], salt_path: &str, vault: Vec<PasswordEntry>, out_path: &str) {
    let key = key_from_master_and_salt(password, salt_path);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let vault_json = serde_json::to_string_pretty(&vault).unwrap();
    let ciphertext = cipher.encrypt(&nonce, vault_json.as_bytes()).unwrap();

    let mut file = File::create(out_path).unwrap();
    file.write_all(&nonce).unwrap();
    file.write_all(&ciphertext).unwrap();
}

fn main() {
    let password = b"hello";
    let salt_path = "salt.bin";
    let out_path = "vault.enc";

    create_master(password, salt_path);

    let vault = build_vault(
        "example.com".to_string(),
        "user123".to_string(),
        "passw0rd!".to_string(),
        Some("Some notes".to_string()),
    );

    encrypt_and_save_vault(password, salt_path, vault, out_path);
}
