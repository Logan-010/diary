use clap::{Parser, Subcommand, value_parser};

#[derive(Parser)]
#[command(name = env!("CARGO_PKG_NAME"))]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = env!("CARGO_PKG_DESCRIPTION"))]
#[command(author = env!("CARGO_PKG_AUTHORS"))]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Clone)]
pub enum Command {
    /// Create a new diary
    New {
        /// Name for new diary
        name: String,
    },
    /// Open a diary
    Open {
        /// Name of diary to open
        name: String,
    },
    /// Close close a diary
    Close {
        /// Name of diary to close
        name: String,

        /// Level of compression to use
        #[arg(long, short = 'L', required = false, default_value_t = 1, value_parser=value_parser!(u32).range(1..=9))]
        level: u32,
    },
    /// Manipulate entries
    Entry {
        #[clap(subcommand)]
        entry_command: EntryCommand,
    },
}

#[derive(Subcommand, Clone)]
pub enum EntryCommand {
    /// Add an entry
    Add {
        /// Name for entry
        name: String,
    },
    /// Remove an entry
    Remove {
        /// Name of entry to remove
        name: String,
    },
    /// List entries
    List,
    /// Search for entries by their name
    Search {
        /// Entries name to find
        query: String,
    },
}
