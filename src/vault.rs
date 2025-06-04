use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use serde_json;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use crate::structs::PasswordEntry;

pub fn encrypt_and_save_vault(password: &[u8], salt_path: &str, vault: &[PasswordEntry], out_path: &str) {
    let key = crate::master::key_from_master_and_salt(password, salt_path);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let vault_json = serde_json::to_string_pretty(vault).unwrap();
    let ciphertext = cipher.encrypt(&nonce, vault_json.as_bytes()).unwrap();

    let mut file = File::create(out_path).unwrap();
    file.write_all(&nonce).unwrap();
    file.write_all(&ciphertext).unwrap();
}

pub fn decrypt_vault(password: &[u8], salt_path: &str, in_path: &str) -> Result<Vec<PasswordEntry>, &'static str> {
    let key = crate::master::key_from_master_and_salt(password, salt_path);
    let cipher = Aes256Gcm::new(&key);
    let mut file = File::open(in_path).map_err(|_| "File not found")?;
    let mut nonce_bytes = [0u8; 12];
    file.read_exact(&mut nonce_bytes).map_err(|_| "Failed to read nonce")?;
    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext).map_err(|_| "Failed to read ciphertext")?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| "Decryption failed")?;
    serde_json::from_slice(&plaintext).map_err(|_| "JSON parse failed")
}

pub fn add_to_vault(password: &[u8], salt_path: &str, new_entry: PasswordEntry, vault_path: &str) {
    let mut vault = if Path::new(vault_path).exists() {
        decrypt_vault(password, salt_path, vault_path).unwrap_or_else(|_| vec![])
    } else {
        Vec::new()
    };

    vault.push(new_entry);
    encrypt_and_save_vault(password, salt_path, &vault, vault_path);
}
