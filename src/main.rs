use cipher::hash_password;
use clap::Parser;
use cli::{Cli, Command, EntryCommand};
use color_eyre::eyre::{Context, bail};
use entries::{Entries, Entry};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use rand::Rng;
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
};
use tar::{Archive, Builder};
use time::OffsetDateTime;
use uuid::Uuid;

mod consts;
use consts::SALT_LENGTH;

mod cipher;
mod cli;
mod entries;

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

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
            let mut diary =
                File::open(format!("{name}.diary")).context("Failed to open diary file")?;

            let key = rpassword::prompt_password("Enter password: ")?;

            let mut salt = [0u8; SALT_LENGTH];
            diary.read_exact(&mut salt)?;

            let key = hash_password(key.as_bytes(), &salt)?;

            let mut decrypted = File::create_new(format!("{name}.tar.gz"))
                .context("Failed to create archive file")?;

            cipher::decrypt(diary, &mut decrypted, key).context("Failed to decrypt")?;

            decrypted
                .seek(SeekFrom::Start(0))
                .context("Failed to seek")?;

            let decompressed = GzDecoder::new(decrypted);
            let mut archive = Archive::new(decompressed);

            archive.unpack(&name).context("Failed to unpack diary")?;

            fs::remove_file(format!("{name}.diary")).context("Failed to remove diary file")?;
            fs::remove_file(format!("{name}.tar.gz")).context("Failed to remove diary archive")?;

            println!("Diary opened.");
        }
        Command::Close { name, level } => {
            let diary_handle =
                File::open(format!("{name}/diary.json")).context("Failed to open diary file")?;
            let entries: Entries =
                serde_json::from_reader(diary_handle).context("Failed to deserialize diary")?;

            let archive_file =
                File::create_new(format!("{name}.tar.gz")).context("Failed to create archive")?;
            let compressed = GzEncoder::new(archive_file, Compression::new(level));
            let mut archive = Builder::new(compressed);

            archive.append_dir_all(".", &name)?;

            let mut archive_file = archive.into_inner()?.finish()?;

            archive_file
                .seek(SeekFrom::Start(0))
                .context("Failed to seek")?;

            let mut diary =
                File::create_new(format!("{name}.diary")).context("Failed to create diary file")?;

            let mut salt = [0u8; SALT_LENGTH];
            rand::rng().fill_bytes(&mut salt);

            let key = hash_password(entries.key.as_bytes(), &salt)?;

            diary.write_all(&salt)?;

            cipher::encrypt(archive_file, diary, key).context("Failed to encrypt")?;

            fs::remove_dir_all(&name).context("Failed to remove diary directory")?;
            fs::remove_file(format!("{name}.tar.gz")).context("Failed to remove diary archive")?;

            println!("Diary closed.");
        }
        Command::Entry { entry_command } => {
            let mut entries: Entries = serde_json::from_reader(
                File::open("diary.json").context("Not inside a diary directory")?,
            )
            .context("Failed to deserialize diary")?;

            match entry_command {
                EntryCommand::Add {
                    name,
                    description,
                    location,
                } => {
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
                            location,
                            description,
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
                    for (key, entry) in entries.entries.iter() {
                        println!(
                            "{} ({}):\n\tpath: {}\n\ttimestamp: {}{}{}",
                            key,
                            entry.id,
                            entry.path.display(),
                            entry.timestamp,
                            {
                                match entry.location.as_ref() {
                                    Some(l) => format!("\n\tlocation: {l}"),
                                    None => String::new(),
                                }
                            },
                            {
                                match entry.description.as_ref() {
                                    Some(d) => format!("\n\tdescription: {d}"),
                                    None => String::new(),
                                }
                            },
                        );
                    }
                }
                EntryCommand::Search { query } => {
                    for (key, entry) in entries.entries.iter().filter(|(k, v)| {
                        let matches_key = k.to_lowercase().contains(&query.to_lowercase());
                        let matches_location = v
                            .location
                            .as_ref()
                            .is_some_and(|l| l.to_lowercase().contains(&query.to_lowercase()));
                        let matches_description = v
                            .description
                            .as_ref()
                            .is_some_and(|d| d.to_lowercase().contains(&query.to_lowercase()));
                        matches_key || matches_location || matches_description
                    }) {
                        println!(
                            "{} ({}):\n\tpath: {}\n\ttimestamp: {}{}{}",
                            key,
                            entry.id,
                            entry.path.display(),
                            entry.timestamp,
                            {
                                match entry.location.as_ref() {
                                    Some(l) => format!("\n\tlocation: {l}"),
                                    None => String::new(),
                                }
                            },
                            {
                                match entry.description.as_ref() {
                                    Some(d) => format!("\n\tdescription: {d}"),
                                    None => String::new(),
                                }
                            },
                        );
                    }
                }
            }
        }
    }

    Ok(())
}
