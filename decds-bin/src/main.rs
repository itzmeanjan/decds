use clap::{Parser, Subcommand};
use const_hex;
use decds_lib::{Blob, BlobHeader, DECDS_NUM_ERASURE_CODED_SHARES, ProofCarryingChunk};
use rand::Rng;
use std::{path::PathBuf, process::exit, str::FromStr};

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
    Verify {},
    /// Reconstructs original data blob using erasure-coded proof-carrying chunks
    Repair {},
}

fn prepare_random_target_directory_name<R: Rng + ?Sized>(prefix: &str, rng: &mut R) -> PathBuf {
    let mut rand_suffix = [0u8; 4];
    rng.fill_bytes(&mut rand_suffix);

    let mut res = String::new();
    res.push_str(prefix);
    res.push('-');
    res.push_str(&const_hex::encode(rand_suffix));

    unsafe { PathBuf::from_str(&res).unwrap_unchecked() }
}

fn get_target_directory_path<R: Rng + ?Sized>(blob_path: &PathBuf, opt_target_dir: &Option<PathBuf>, rng: &mut R) -> PathBuf {
    match opt_target_dir {
        Some(path) => match path.try_exists() {
            Ok(ok) => {
                if ok {
                    prepare_random_target_directory_name(unsafe { path.to_str().unwrap_unchecked() }, rng)
                } else {
                    path.clone()
                }
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                exit(1);
            }
        },
        None => prepare_random_target_directory_name(unsafe { blob_path.file_name().unwrap_unchecked().to_str().unwrap_unchecked() }, rng),
    }
}

fn write_blob_metadata(target_dir: &PathBuf, metadata: &BlobHeader) {
    let mut blob_metadata_path = target_dir.clone();
    blob_metadata_path.push("metadata.commit");

    match metadata.to_bytes() {
        Ok(bytes) => {
            if let Err(e) = std::fs::write(blob_metadata_path, bytes) {
                eprintln!("Error: {}", e);
                exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            exit(1);
        }
    }
}

fn write_blob_share(target_dir: &PathBuf, share_id: usize, share: Vec<ProofCarryingChunk>) {
    let mut blob_share_path = target_dir.clone();

    for (chunkset_id, chunk) in share.iter().enumerate() {
        blob_share_path.push(format!("chunkset.{}", chunkset_id));

        match blob_share_path.try_exists() {
            Ok(ok) => {
                if !ok {
                    if let Err(e) = std::fs::create_dir(&blob_share_path) {
                        eprintln!("Error: {}", e);
                        exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                exit(1);
            }
        };

        blob_share_path.push(format!("share{:02}.data", share_id));

        match chunk.to_bytes() {
            Ok(bytes) => {
                if let Err(e) = std::fs::write(&blob_share_path, bytes) {
                    eprintln!("Error: {}", e);
                    exit(1);
                }
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                exit(1);
            }
        };

        blob_share_path.pop();
        blob_share_path.pop();
    }
}

fn format_bytes(bytes: usize) -> String {
    let suffixes = ["B", "KB", "MB", "GB"];
    let mut index = 0;
    let mut size = bytes as f64;

    while size >= 1024.0 && index < suffixes.len() - 1 {
        size /= 1024.0;
        index += 1;
    }

    format!("{:.1}{}", size, suffixes[index])
}

fn main() {
    let cli = DecdsCLI::parse();
    match &cli.command {
        DecdsCommand::Break { blob_path, opt_target_dir } => match std::fs::read(blob_path) {
            Ok(blob_bytes) => {
                println!("Read {:?}", blob_path);
                println!("Size {}", format_bytes(blob_bytes.len()));

                match Blob::new(blob_bytes) {
                    Ok(erasure_coded) => {
                        let metadata = erasure_coded.get_blob_header();
                        println!("BLAKE3 Digest: {}", metadata.get_blob_digest());
                        println!("Blob root commitment: {}", metadata.get_root_commitment());
                        println!("Number of chunksets: {}", metadata.get_num_chunksets());
                        println!("Number of chunks: {}", metadata.get_num_chunks());

                        let mut rng = rand::rng();
                        let target_dir_path = get_target_directory_path(blob_path, opt_target_dir, &mut rng);

                        if let Err(e) = std::fs::DirBuilder::new().recursive(true).create(&target_dir_path) {
                            eprintln!("Error: {}", e);
                            exit(1);
                        }

                        println!("Writing erasure-coded chunks ...");

                        write_blob_metadata(&target_dir_path, metadata);
                        (0..DECDS_NUM_ERASURE_CODED_SHARES).for_each(|share_id| {
                            write_blob_share(&target_dir_path, share_id, erasure_coded.get_share(share_id).unwrap());
                        });

                        println!("Erasure-coded chunks placed in {:?}", &target_dir_path);
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                exit(1);
            }
        },
        DecdsCommand::Verify {} => {}
        DecdsCommand::Repair {} => {}
    }
}
