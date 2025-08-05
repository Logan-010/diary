use anyhow::{Context, bail};
use cipher::hash_password;
use clap::Parser;
use cli::{Cli, Command, EntryCommand};
use entries::{Entries, Entry};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use rand::RngCore;
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
};
use tar::{Archive, Builder};
use time::OffsetDateTime;
use uuid::Uuid;

mod cipher;
mod cli;
mod entries;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::New { name } => {
            let key = {
                let p1 = rpassword::prompt_password("Enter password: ")?;
                let p2 = rpassword::prompt_password("Re-enter password: ")?;

                if p1 != p2 {
                    bail!("Passwords do not match");
                }

                p1
            };

            fs::create_dir(&name).context("Failed to create directory for diary")?;

            let mut diary_handle = File::create_new(format!("{name}/diary.json"))
                .context("Failed to create diary file")?;

            let entries = Entries {
                entries: HashMap::default(),
                key,
            };

            serde_json::to_writer(&mut diary_handle, &entries)
                .context("Failed to save diary file")?;

            println!("Created diary {name}");
        }
        Command::Open { name } => {
            let key = rpassword::prompt_password("Enter password: ")?;

            let mut diary =
                File::open(format!("{name}.diary")).context("Failed to open diary file")?;
            let mut decrypted = File::create_new(format!("{name}.tar.gz"))
                .context("Failed to create temporary diary file")?;

            let mut salt = [0u8; 16];
            diary.read_exact(&mut salt)?;
            let mut nonce = [0u8; 19];
            diary.read_exact(&mut nonce)?;

            let key_hash = cipher::hash_password(key.as_bytes(), &salt)?;

            cipher::decrypt(diary, &mut decrypted, &key_hash, &nonce)
                .context("Failed to decrypt")?;

            decrypted.flush()?;

            decrypted.seek(SeekFrom::Start(0))?;

            let decompressed = GzDecoder::new(decrypted);
            let mut archive = Archive::new(decompressed);

            archive.unpack(&name).context("Failed to unpack diary")?;

            fs::remove_file(format!("{name}.tar.gz"))
                .context("Failed to remove temporary diary file")?;
            fs::remove_file(format!("{name}.diary")).context("Failed to remove diary file")?;

            println!("Diary opened.");
        }
        Command::Close { name, level } => {
            let diary_handle =
                File::open(format!("{name}/diary.json")).context("Failed to open diary file")?;
            let entries: Entries =
                serde_json::from_reader(diary_handle).context("Failed to deserialize diary")?;

            let out = File::create_new(format!("{name}.tar.gz"))
                .context("Failed to create diary file")?;

            let compressed = GzEncoder::new(out, Compression::new(level));
            let mut archive = Builder::new(compressed);

            archive.append_dir_all(".", &name)?;
            archive.finish()?;

            let mut unencrypted = archive
                .into_inner()
                .context("Failed to extract inner stream to archive")?
                .finish()
                .context("Failed to finalize compression")?;

            let mut diary =
                File::create_new(format!("{name}.diary")).context("Failed to create diary file")?;

            let mut salt = [0u8; 16];
            rand::rng().fill_bytes(&mut salt);
            let mut nonce = [0u8; 19];
            rand::rng().fill_bytes(&mut nonce);

            let key_hash = hash_password(entries.key.as_bytes(), &salt)?;

            diary.write_all(&salt)?;
            diary.write_all(&nonce)?;

            unencrypted.seek(SeekFrom::Start(0))?;

            cipher::encrypt(unencrypted, &mut diary, &key_hash, &nonce)
                .context("Failed to encrypt file")?;

            diary.flush()?;

            fs::remove_dir_all(&name).context("Failed to remove diary directory")?;
            fs::remove_file(format!("{name}.tar.gz"))
                .context("Failed to remove temporary diary file")?;

            println!("Diary closed.");
        }
        Command::Entry { entry_command } => {
            let mut entries: Entries = serde_json::from_reader(
                File::open("diary.json").context("Not inside a diary directory")?,
            )
            .context("Failed to deserialize diary")?;

            match entry_command {
                EntryCommand::Add { name } => {
                    let id = Uuid::new_v4();
                    let timestamp = OffsetDateTime::now_local()?;
                    let path = PathBuf::from(format!("{id}.md"));

                    File::create_new(&path).context("Failed to create new file for entry")?;

                    println!("Created entry {} at path {}", name, path.display());

                    entries.entries.insert(
                        name,
                        Entry {
                            id,
                            path,
                            timestamp,
                        },
                    );

                    serde_json::to_writer(
                        File::create("diary.json.new")
                            .context("Failed to create new diary file")?,
                        &entries,
                    )
                    .context("Failed to save diary file")?;
                    fs::rename("diary.json.new", "diary.json")
                        .context("Failed to replace old diary file")?;
                }
                EntryCommand::Remove { name } => {
                    match entries.entries.remove(&name) {
                        Some(entry) => {
                            fs::remove_file(entry.path)?;
                            println!("Removed entry {} ({})", name, entry.id);
                        }
                        None => println!("Entry does not exist :("),
                    }

                    serde_json::to_writer(
                        File::create("diary.json.new")
                            .context("Failed to create new diary file")?,
                        &entries,
                    )
                    .context("Failed to save diary file")?;
                    fs::rename("diary.json.new", "diary.json")
                        .context("Failed to replace old diary file")?;
                }
                EntryCommand::List => {
                    for entry in entries.entries.iter() {
                        println!(
                            "{} ({}):\n\tpath: {}\n\tcreated at: {}",
                            entry.0,
                            entry.1.id,
                            entry.1.path.display(),
                            entry.1.timestamp
                        );
                    }
                }
                EntryCommand::Search { query } => {
                    for key in entries.entries.keys().filter(|k| k.contains(&query)) {
                        let entry = entries.entries.get(key).unwrap();

                        println!(
                            "{} ({}):\n\tpath: {}\n\tcreated at: {}",
                            key,
                            entry.id,
                            entry.path.display(),
                            entry.timestamp
                        );
                    }
                }
            }
        }
    }

    Ok(())
}
