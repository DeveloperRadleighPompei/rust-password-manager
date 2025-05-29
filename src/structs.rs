use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct PasswordEntry {
    pub name: String,
    pub username: String,
    pub password: String,
    pub notes: Option<String>,
}
