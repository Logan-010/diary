use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct Entries {
    pub entries: HashMap<String, Entry>,
    pub key: String,
}

#[derive(Hash, Serialize, Deserialize)]
pub struct Entry {
    pub id: Uuid,
    pub path: PathBuf,
    pub timestamp: OffsetDateTime,
    pub location: Option<String>,
    pub description: Option<String>,
}
