use aes_gcm::{Aes256Gcm, KeyInit, aead::AeadInPlace, Nonce};
use aes_gcm::aead::generic_array::GenericArray;
use clap::Parser;
use rand::{RngCore, thread_rng};
use std::fs::{self, File};
use std::io::{Write, ErrorKind};
use std::process;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "Encrypts a vTPM state file into an SVSMvTPM image format")]
struct Args {
    /// The 32-byte secret key
    #[arg(short = 'k', long = "key")]
    key_file: PathBuf,

    /// Path to the raw vTPM state binary file (NVChip) to be encrypted
    #[arg(short = 's', long = "state")]
    state: String,

    /// Output directory path to the image file
    #[arg(short = 'o', long = "output")]
    output_dir: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Get the secret key of size 32 from the file.
    let secret_key = match fs::read(&args.key_file) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                eprintln!(
                    "Error: The key file '{}' must contain exactly 32 raw bytes (256-bits). Got {} bytes.",
                    args.key_file.display(),
                    bytes.len()
                );
                process::exit(1);
            }
            bytes
        }
        Err(e) => {
            eprintln!("Error: Could not read key file '{}': {}", args.key_file.display(), e);
            process::exit(1);
        }
    };

    let raw_vtpm_state = match fs::read(&args.state) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error: Could not read input file '{}': {}", args.state, e);
            process::exit(1);
        }
    };

    // Generate a random 12-byte IV (Nonce) cryptographically
    let mut iv = [0u8; 12];
    thread_rng().fill_bytes(&mut iv);

    let mut payload = raw_vtpm_state.clone();
    let payload_size = payload.len() as u32;

    // Initialize cipher with our validated secret key
    let key_array = GenericArray::from_slice(&secret_key);
    let cipher = Aes256Gcm::new(key_array);

    let nonce = Nonce::from_slice(&iv);

    // Encrypt in-place and get the 16-byte authentication tag
    let tag = cipher
        .encrypt_in_place_detached(nonce, b"",
                                   &mut payload)
        .map_err(|e| format!("Encryption failure: {:?}", e))?;

    // Build a 64 byte header
    let mut header = Vec::with_capacity(64);

    // 0x00: Magic "SVSMvTPM" (8 bytes)
    header.extend_from_slice(b"SVSMvTPM");

    // 0x08: Version 1 (2 bytes, Little-Endian)
    header.extend_from_slice(&1u16.to_le_bytes());

    // 0x0A: Cipher ID 1 (2 bytes, Little-Endian)
    header.extend_from_slice(&1u16.to_le_bytes());

    // 0x0C: Payload Size (4 bytes, Little-Endian)
    header.extend_from_slice(&payload_size.to_le_bytes());

    // 0x10: IV (12 bytes)
    header.extend_from_slice(&iv);

    // 0x1C: Tag (16 bytes)
    header.extend_from_slice(tag.as_slice());

    // 0x2C: Reserved (20 bytes of zeros)
    header.extend_from_slice(&[0u8; 20]);

    assert_eq!(header.len(), 64, "Header must be exactly 64 bytes!");


    // Assemble header and encrypted payload and pad to 4096 bytes
    let target_dir = args.output_dir.unwrap_or_else(|| PathBuf::from("."));

    if !target_dir.exists() && let Err(e) = fs::create_dir_all(&target_dir) {
        match e.kind() {
            ErrorKind::PermissionDenied => {
                eprintln!("Error: Permission denied while trying to create directory '{}'.", target_dir.display());
                eprintln!("Please check your write permissions for this path or run with elevated privileges (e.g., sudo).");
                std::process::exit(1);
                }
            _ => {
                eprintln!("Error: Failed to create directory '{}': {}", target_dir.display(), e);
                std::process::exit(1);
            }
        }
    }

    let mut final_image = Vec::new();
    final_image.extend_from_slice(&header);
    final_image.extend_from_slice(&payload);

    // Pad to 4096-byte sectors
    let current_size = final_image.len();
    let remainder = current_size % 4096;
    if remainder != 0 {
        let padding_needed = 4096 - remainder;
        final_image.extend(std::iter::repeat_n(0u8,padding_needed));
    }

    assert_eq!(final_image.len() % 4096, 0, "Image size must be a multiple of 4096!");

    // Output the final image
    let mut output_filename = target_dir;
    output_filename.push("vtpm_state.img");
    let mut file = File::create(&output_filename)?;
    file.write_all(&final_image)?;

    println!("Success: '{:?}' created successfully.", output_filename);
    println!("Payload size: {} bytes", payload_size);
    println!("Total image size (aligned to 4096): {} bytes", final_image.len());

    Ok(())
}