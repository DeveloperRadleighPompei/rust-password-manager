use argon2_kdf::{Algorithm, Hasher};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

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

fn encrypt_and_save_vault(password: &[u8], salt_path: &str, vault: &[PasswordEntry], out_path: &str) {
    let key = key_from_master_and_salt(password, salt_path);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bit nonce
    let vault_json = serde_json::to_string_pretty(&vault).unwrap();
    let ciphertext = cipher.encrypt(&nonce, vault_json.as_bytes()).unwrap();

    let mut file = File::create(out_path).unwrap();
    file.write_all(&nonce).unwrap();         // Save nonce first
    file.write_all(&ciphertext).unwrap();    // Then ciphertext
}

fn decrypt_vault(password: &[u8], salt_path: &str, in_path: &str) -> Result<Vec<PasswordEntry>, &'static str> {
    let key = key_from_master_and_salt(password, salt_path);
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

fn add_to_vault(password: &[u8], salt_path: &str, new_entry: PasswordEntry, vault_path: &str) {
    let mut vault = if Path::new(vault_path).exists() {
        decrypt_vault(password, salt_path, vault_path).unwrap_or_else(|_| vec![])
    } else {
        Vec::new()
    };

    vault.push(new_entry);
    encrypt_and_save_vault(password, salt_path, &vault, vault_path);
}

fn login(salt_path: &str, vault_path: &str) -> Option<Vec<u8>> {
    println!("Enter master password:");
    let mut password = String::new();
    std::io::stdin().read_line(&mut password).expect("Failed to read password");
    let password = password.trim().to_string();
    let password_bytes = password.as_bytes();

    if Path::new(vault_path).exists() {
        match decrypt_vault(password_bytes, salt_path, vault_path) {
            Ok(_) => Some(password_bytes.to_vec()),
            Err(e) => {
                println!("Login failed: {e}");
                None
            }
        }
    } else {
        println!("No vault found. Creating new one.");
        create_master(password_bytes, salt_path);
        Some(password_bytes.to_vec())
    }
}

fn get_input(prompt: &str) -> String {
    print!("{prompt}: ");
    io::stdout().flush().unwrap();
    let mut s = String::new();
    io::stdin().read_line(&mut s).unwrap();
    s.trim().to_string()
}

fn main() {
    let salt_path = "salt.bin";
    let vault_path = "vault.enc";

    let password = match login(salt_path, vault_path) {
        Some(p) => p,
        None => return,
    };

    loop {
        println!("\nOptions: [a] Add | [v] View | [q] Quit");
        let choice = get_input("Choose");

        match choice.as_str() {
            "q" => {
                println!("Goodbye.");
                break;
            }
            "a" => {
                let name = get_input("Service Name");
                let username = get_input("Username");
                let pw = get_input("Password");
                let notes = get_input("Notes (optional)");
                let notes_opt = if notes.is_empty() { None } else { Some(notes) };

                let entry = PasswordEntry {
                    name,
                    username,
                    password: pw,
                    notes: notes_opt,
                };

                add_to_vault(&password, salt_path, entry, vault_path);
                println!("Entry added.");
            }
            "v" => {
                match decrypt_vault(&password, salt_path, vault_path) {
                    Ok(vault) => {
                        if vault.is_empty() {
                            println!("Vault is empty.");
                        } else {
                            for (i, entry) in vault.iter().enumerate() {
                                println!(
                                    "\n#{}: {}\n  Username: {}\n  Password: {}\n  Notes: {}",
                                    i + 1,
                                    entry.name,
                                    entry.username,
                                    entry.password,
                                    entry.notes.clone().unwrap_or("None".into())
                                );
                            }
                        }
                    }
                    Err(e) => println!("Failed to read vault: {e}"),
                }
            }
            _ => println!("Invalid option."),
        }
    }
}
