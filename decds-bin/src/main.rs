mod errors;

use crate::errors::DecdsError;
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
    Verify {
        /// Directory path to erasure-coded proof-carrying chunks
        blob_dir_path: PathBuf,
    },
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

fn read_blob_metadata(blob_metadata_path: &PathBuf) -> BlobHeader {
    match std::fs::read(blob_metadata_path) {
        Ok(bytes) => match BlobHeader::from_bytes(&bytes) {
            Ok((blob_header, n)) => {
                if n != bytes.len() {
                    eprintln!(
                        "Erasure-coded blob metadata file {:?} is {} bytes longer than it should be",
                        blob_metadata_path,
                        bytes.len() - n
                    );
                    exit(1);
                }

                blob_header
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                exit(1);
            }
        },
        Err(e) => {
            eprintln!("Error: {}", e);
            exit(1);
        }
    }
}

fn read_proof_carrying_chunk(chunk_path: &PathBuf) -> Result<ProofCarryingChunk, DecdsError> {
    match std::fs::read(chunk_path) {
        Ok(bytes) => match ProofCarryingChunk::from_bytes(&bytes) {
            Ok((chunk, n)) => {
                if n != bytes.len() {
                    Err(DecdsError::FailedToReadProofCarryingChunk(format!(
                        "Erasure-coded chunk file {:?} is {} bytes longer than it should be",
                        chunk_path,
                        bytes.len() - n
                    )))
                } else {
                    Ok(chunk)
                }
            }
            Err(e) => Err(DecdsError::FailedToReadProofCarryingChunk(e.to_string())),
        },
        Err(e) => Err(DecdsError::FailedToReadProofCarryingChunk(e.to_string())),
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

                        println!("Writing blob metadata and erasure-coded chunks...");

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
        DecdsCommand::Verify { blob_dir_path } => {
            if !blob_dir_path.is_dir() {
                eprintln!("{:?} is not a directory", blob_dir_path);
                exit(1);
            }

            match blob_dir_path.try_exists() {
                Ok(ok) => {
                    if !ok {
                        eprintln!("Erasure-coded blob directory {:?} doesn't exist", blob_dir_path);
                        exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    exit(1);
                }
            };

            let mut blob_metadata_path = blob_dir_path.clone();
            blob_metadata_path.push("metadata.commit");

            println!("Looking for erasure-coded blob metadata file {:?}...", blob_metadata_path);
            let blob_metadata = read_blob_metadata(&blob_metadata_path);

            println!("Original blob size: {}", format_bytes(blob_metadata.get_blob_size()));
            println!("Original blob BLAKE3 Digest: {}", blob_metadata.get_blob_digest());
            println!("Original blob root commitment: {}", blob_metadata.get_root_commitment());
            println!("Original blob number of chunksets: {}", blob_metadata.get_num_chunksets());
            println!("Original blob number of chunks: {}", blob_metadata.get_num_chunks());

            let mut blob_share_path = blob_dir_path.clone();
            let mut indent = String::new();
            let mut total_num_valid_chunks = 0;

            println!("Verifying erasure-coded proof-carrying chunks...\n");
            println!("{}", blob_share_path.to_str().unwrap());

            (0..blob_metadata.get_num_chunksets()).for_each(|chunkset_id| {
                blob_share_path.push(format!("chunkset.{}", chunkset_id));
                indent.push('\t');

                let (console_log, num_valid_shares) =
                    (0..DECDS_NUM_ERASURE_CODED_SHARES).fold((String::new(), 0usize), |(mut console_log, mut num_valid_shares), share_id| {
                        blob_share_path.push(format!("share{:02}.data", share_id));
                        indent.push('\t');

                        let share_stat_log = if let Ok(ok) = blob_share_path.try_exists()
                            && ok
                        {
                            match read_proof_carrying_chunk(&blob_share_path) {
                                Ok(chunk) => {
                                    if blob_metadata.validate_chunk(&chunk) {
                                        num_valid_shares += 1;
                                        format!("{}- {}\t✅", indent, blob_share_path.file_name().unwrap().to_str().unwrap())
                                    } else {
                                        format!(
                                            "{}- {}\t🚫\tError: proof verification failed",
                                            indent,
                                            blob_share_path.file_name().unwrap().to_str().unwrap()
                                        )
                                    }
                                }
                                Err(e) => {
                                    format!("{}- {}\t🚫\tError: {}", indent, blob_share_path.file_name().unwrap().to_str().unwrap(), e)
                                }
                            }
                        } else {
                            format!(
                                "{}- {}\t🚫\tError: chunk not present",
                                indent,
                                blob_share_path.file_name().unwrap().to_str().unwrap()
                            )
                        };

                        blob_share_path.pop();
                        indent.pop();

                        console_log.push_str(&share_stat_log);
                        console_log.push('\n');

                        (console_log, num_valid_shares)
                    });

                println!(
                    "{}- {}\t({}/{})",
                    indent,
                    blob_share_path.file_name().unwrap().to_str().unwrap(),
                    num_valid_shares,
                    DECDS_NUM_ERASURE_CODED_SHARES
                );
                println!("{}", console_log);

                total_num_valid_chunks += num_valid_shares;

                blob_share_path.pop();
                indent.pop();
            });

            println!(
                "Found {}/{} valid chunks in {:?}.",
                total_num_valid_chunks,
                blob_metadata.get_num_chunks(),
                blob_dir_path
            );
        }
        DecdsCommand::Repair {} => {
            todo!("Not implemented yet!")
        }
    }
}
