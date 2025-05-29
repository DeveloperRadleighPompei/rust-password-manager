mod structs;
mod vault;
mod master;

use std::path::Path;

use console::{Style, Emoji};
use dialoguer::{theme::ColorfulTheme, Input, Password, Select};
use indicatif::{ProgressBar, ProgressStyle};

use structs::PasswordEntry;

fn get_input(prompt: &str) -> String {
    Input::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .interact_text()
        .unwrap()
}

fn main() {
    let salt_path = "salt.bin";
    let vault_path = "vault.enc";

    let bold = Style::new().bold();
    let green = Style::new().green();
    let red = Style::new().red();
    let yellow = Style::new().yellow();
    let lock = Emoji("🔐", "");
    let key = Emoji("🔑", "");

    println!("{} {}", lock, bold.apply_to("Welcome to VaultSafe CLI"));

    let password = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter master password")
        .interact()
        .unwrap();

    let password_bytes = password.trim().as_bytes();

    let password_bytes = match master::login(password_bytes, salt_path, vault_path) {
        Some(p) => p,
        None => {
            println!("{}", red.apply_to("❌ Login failed."));
            return;
        }
    };

    loop {
        println!("\n{}", bold.apply_to("What would you like to do?"));
        let options = &["➕ Add Entry", "📂 View Vault", "❌ Quit"];
        let selection = Select::with_theme(&ColorfulTheme::default())
            .items(options)
            .default(0)
            .interact()
            .unwrap();

        match selection {
            0 => {
                let name = get_input("Service Name");
                let username = get_input("Username");
                let pw = Password::with_theme(&ColorfulTheme::default())
                    .with_prompt("Password")
                    .interact()
                    .unwrap();
                let notes = get_input("Notes (optional)");
                let notes_opt = if notes.is_empty() { None } else { Some(notes) };

                let entry = PasswordEntry {
                    name,
                    username,
                    password: pw,
                    notes: notes_opt,
                };

                let pb = ProgressBar::new_spinner();
                pb.set_message("Encrypting and saving entry...");
                pb.enable_steady_tick(std::time::Duration::from_millis(120));
                pb.set_style(ProgressStyle::default_spinner().template("{spinner} {msg}").unwrap());

                vault::add_to_vault(&password_bytes, salt_path, entry, vault_path);

                pb.finish_with_message(green.apply_to("✔ Entry added successfully").to_string());
            }

            1 => match vault::decrypt_vault(&password_bytes, salt_path, vault_path) {
                Ok(vault) => {
                    if vault.is_empty() {
                        println!("{}", yellow.apply_to("⚠ Vault is empty."));
                    } else {
                        println!("{}", bold.apply_to("\n🔓 Vault Contents:"));
                        for (i, entry) in vault.iter().enumerate() {
                            println!(
                                "{} {}",
                                bold.apply_to(format!("\n#{}:", i + 1)),
                                green.apply_to(&entry.name)
                            );
                            println!("  {} {}", bold.apply_to("Username:"), entry.username);
                            println!("  {} {}", bold.apply_to("Password:"), entry.password);
                            println!(
                                "  {} {}",
                                bold.apply_to("Notes:"),
                                entry.notes.clone().unwrap_or("None".into())
                            );
                        }
                    }
                }
                Err(e) => println!("{} Failed to read vault: {}", red.apply_to("❌"), e),
            },

            2 => {
                println!("{}", green.apply_to("👋 Goodbye."));
                break;
            }

            _ => println!("{}", red.apply_to("❌ Invalid option.")),
        }
    }
}
