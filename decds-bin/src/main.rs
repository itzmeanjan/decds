mod errors;
mod handlers;
mod utils;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "decds", version, about, long_about = None)]
struct DecdsCLI {
    #[command(subcommand)]
    command: DecdsCommand,
}

#[derive(Subcommand)]
enum DecdsCommand {
    /// Splits given data blob into small erasure-coded chunks, carrying proof of inclusion
    Break {
        /// Path of source data blob
        #[arg(short)]
        blob_path: PathBuf,
        /// Optional target directory to put erasure-coded chunks
        #[arg(short)]
        opt_target_dir: Option<PathBuf>,
    },
    /// Validate proof of inclusion for erasure-coded chunks
    Verify {
        /// Directory path to erasure-coded proof-carrying chunks
        blob_dir_path: PathBuf,
    },
    /// Reconstructs original data blob using erasure-coded proof-carrying chunks
    Repair {
        /// Directory path to erasure-coded chunks
        #[arg(short)]
        chunk_dir_path: PathBuf,
        /// Optional target directory to put repaired chunksets and blob
        #[arg(short)]
        opt_target_dir: Option<PathBuf>,
    },
}

fn main() {
    let cli = DecdsCLI::parse();
    match &cli.command {
        DecdsCommand::Break { blob_path, opt_target_dir } => handlers::handle_break_command(blob_path, opt_target_dir),
        DecdsCommand::Verify { blob_dir_path } => handlers::handle_verify_command(blob_dir_path),
        DecdsCommand::Repair {
            chunk_dir_path,
            opt_target_dir,
        } => handlers::handle_repair_command(chunk_dir_path, opt_target_dir),
    }
}
