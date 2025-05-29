use eframe::{egui, App};
use egui::{CentralPanel, ScrollArea, TextEdit};
use crate::{structs::PasswordEntry, vault, master};
use std::path::Path;

pub struct VaultApp {
    password: String,
    salt_path: String,
    vault_path: String,
    vault: Vec<PasswordEntry>,

    name_input: String,
    username_input: String,
    password_input: String,
    notes_input: String,

    logged_in: bool,
    error_message: Option<String>,
}

impl VaultApp {
    pub fn new(salt_path: &str, vault_path: &str) -> Self {
        Self {
            password: String::new(),
            salt_path: salt_path.to_owned(),
            vault_path: vault_path.to_owned(),
            vault: Vec::new(),

            name_input: String::new(),
            username_input: String::new(),
            password_input: String::new(),
            notes_input: String::new(),

            logged_in: false,
            error_message: None,
        }
    }
}

impl App for VaultApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        CentralPanel::default().show(ctx, |ui| {
            if !self.logged_in {
                ui.heading("Enter Master Password");

                let pw_edit = ui.add(TextEdit::singleline(&mut self.password).password(true));

                if ui.button("Login").clicked()
                    || (pw_edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                {
                    let pw_bytes = self.password.as_bytes();

                    if Path::new(&self.vault_path).exists() {
                        match vault::decrypt_vault(pw_bytes, &self.salt_path, &self.vault_path) {
                            Ok(v) => {
                                self.vault = v;
                                self.logged_in = true;
                                self.error_message = None;
                            }
                            Err(e) => {
                                self.error_message = Some(format!("Login failed: {}", e));
                            }
                        }
                    } else {
                        // Vault file missing, create master and empty vault
                        master::create_master(pw_bytes, &self.salt_path);
                        self.vault = Vec::new();
                        self.logged_in = true;
                        vault::encrypt_and_save_vault(pw_bytes, &self.salt_path, &self.vault, &self.vault_path);
                        self.error_message = None;
                    }
                }

                if let Some(err) = &self.error_message {
                    ui.colored_label(egui::Color32::RED, err);
                }
            } else {
                ui.heading("Your Vault");

                ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                    for (i, entry) in self.vault.iter().enumerate() {
                        ui.group(|ui| {
                            ui.label(format!("#{}: {}", i + 1, entry.name));
                            ui.label(format!("Username: {}", entry.username));
                            ui.label(format!("Password: {}", entry.password));
                            ui.label(format!("Notes: {}", entry.notes.as_deref().unwrap_or("None")));
                        });
                    }
                });

                ui.separator();

                ui.heading("Add New Entry");

                ui.horizontal(|ui| {
                    ui.label("Name:");
                    ui.text_edit_singleline(&mut self.name_input);
                });
                ui.horizontal(|ui| {
                    ui.label("Username:");
                    ui.text_edit_singleline(&mut self.username_input);
                });
                ui.horizontal(|ui| {
                    ui.label("Password:");
                    ui.text_edit_singleline(&mut self.password_input);
                });
                ui.horizontal(|ui| {
                    ui.label("Notes:");
                    ui.text_edit_singleline(&mut self.notes_input);
                });

                if ui.button("Add Entry").clicked() {
                    if self.name_input.trim().is_empty()
                        || self.username_input.trim().is_empty()
                        || self.password_input.trim().is_empty()
                    {
                        self.error_message = Some("Name, Username and Password are required.".to_string());
                    } else {
                        let entry = PasswordEntry {
                            name: self.name_input.trim().to_string(),
                            username: self.username_input.trim().to_string(),
                            password: self.password_input.trim().to_string(),
                            notes: if self.notes_input.trim().is_empty() {
                                None
                            } else {
                                Some(self.notes_input.trim().to_string())
                            },
                        };
                        self.vault.push(entry);

                        // Save updated vault
                        vault::encrypt_and_save_vault(
                            self.password.as_bytes(),
                            &self.salt_path,
                            &self.vault,
                            &self.vault_path,
                        );

                        self.name_input.clear();
                        self.username_input.clear();
                        self.password_input.clear();
                        self.notes_input.clear();
                        self.error_message = None;
                    }
                }

                if ui.button("Quit").clicked() {
                    std::process::exit(0);
                }

                if let Some(err) = &self.error_message {
                    ui.colored_label(egui::Color32::RED, err);
                }
            }
        });
    }
}
