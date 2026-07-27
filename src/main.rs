use aes_gcm::{Aes256Gcm, KeyInit, aead::AeadInPlace, Nonce};
use aes_gcm::aead::generic_array::GenericArray;
use clap::Parser;
use rand::{RngCore, thread_rng};
use std::fs::{self, File};
use std::io::{Write, ErrorKind};
use std::process::{self, Command};
use std::path::PathBuf;

// Standardized UUID Constants used to route and index metadata blocks in the header
const UUID_SECRET_STORAGE: &str = "bc27ddb0-0b61-4fa3-979a-ca81f4a476bc";
const UUID_SESSION_NONCE: &str = "aabbccdd-1122-3344-5566-77889900aabb";

/// Dynamically locates the compiled cocoonfs binary from the workspace sibling target folders
/// or falls back to the system PATH.
fn find_cocoonfs_binary() -> PathBuf {
    // Check local debug target path in sibling workspace
    let debug_path = PathBuf::from("../cocoon-tpm/target/debug/cocoonfs");
    if debug_path.exists() {
        return debug_path;
    }

    // Check local release target path
    let release_path = PathBuf::from("../cocoon-tpm/target/release/cocoonfs");
    if release_path.exists() {
        return release_path;
    }

    // Fallback to system PATH
    PathBuf::from("cocoonfs")
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Encrypts a vTPM state file into SVSMvTPM or CocoonFS formats")]
struct Args {
    /// The 32-byte secret key file used to encrypt/format the volume
    #[arg(short = 'k', long = "key")]
    key_file: PathBuf,

    /// Path to the raw vTPM state binary file (NVChip) to be encrypted
    #[arg(short = 's', long = "state")]
    state: String,

    /// Output directory path to the image file
    #[arg(short = 'o', long = "output")]
    output_dir: Option<PathBuf>,

    /// Format and encrypt as a native CocoonFS image instead of legacy SVSMvTPM raw format
    #[arg(short = 'c', long = "cocoonfs")]
    cocoonfs: bool,

    /// Unique Resource ID (KBS Path) to store in the CocoonFS unencrypted header
    #[arg(short = 'r', long = "resource-id")]
    resource_id: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Verify key file size of 32 bytes
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

    let target_dir = args.output_dir.unwrap_or_else(|| PathBuf::from("."));
    if !target_dir.exists() {
        fs::create_dir_all(&target_dir).map_err(|e| {
            format!("Error: Failed to create output directory '{}': {}", target_dir.display(), e)
        })?;
    }

    let mut output_filename = target_dir;
    output_filename.push("vtpm_state.img");

    if args.cocoonfs {
        // ---------------------------------------------------------------------
        // COCOONFS MODE: Format and Encrypt into CocoonFS via CLI process
        // ---------------------------------------------------------------------
        println!("=====================================================================");
        println!("             CREATING ENCRYPTED COCOONFS IMAGE                       ");
        println!("=====================================================================");
        println!("[+] Target image: {:?}", output_filename);

        let cocoonfs_bin = find_cocoonfs_binary();
        println!("[+] Using cocoonfs executable: {:?}", cocoonfs_bin);

        // Pre-create and allocate the blank image file to 10MB capacity
        // We wrap this in a nested scope block so the file handle is explicitly closed and dropped,
        // releasing any OS write locks and committing the 10MB size to disk before we spawn the command.
        let image_size = 10 * 1024 * 1024; // 10MB
        {
            let file = File::create(&output_filename)?;
            file.set_len(image_size)?;
        }
        println!("[+] Pre-allocated 10MB virtual disk file on host");

        // Helper helper function to run commands with polite missing-binary feedback
        let run_command = |mut cmd: Command, step_desc: &str| -> Result<(), Box<dyn std::error::Error>> {
            match cmd.status() {
                Ok(status) => {
                    if !status.success() {
                        eprintln!("Error: Failed during step '{}'", step_desc);
                        process::exit(1);
                    }
                    Ok(())
                }
                Err(ref e) if e.kind() == ErrorKind::NotFound => {
                    eprintln!("\nError: The 'cocoonfs' CLI utility was not found.");
                    eprintln!("Please build the cocoonfs-cli utility inside the cocoon-tpm folder first:");
                    eprintln!("  1. cd ../cocoon-tpm");
                    eprintln!("  2. cargo build -p cocoonfs-cli");
                    eprintln!("\nOnce compiled, this tool will auto-detect and run it successfully.");
                    process::exit(1);
                }
                Err(e) => Err(e.into()),
            }
        };

        // Convert the 32-byte secret key to a hex string for direct command injection
        let secret_key_hex = hex::encode(&secret_key);

        // 1. Format the CocoonFS volume (mkfs)
        println!("[*] Formatting volume...");
        let mut cmd = Command::new(&cocoonfs_bin);
        cmd.args(&[
            "-f", // Force raw sector layout (128-byte alignment)
            "--image", output_filename.to_str().unwrap(),
            "mkfs",
            "--key", &secret_key_hex, // Pass key directly as a hex string!
            "--cipher", "aes",
            "--hash-family", "sha2",
            "--target-security-strength", "256",
            "--salt", "01010101010101010101010101010101", // Standard 16-byte hex-encoded salt
            "--image-size", "10M", // Explicitly specify 10MB image size to format
            "--aux-fs-metadata-extra-reserve-capacity", "1024",
        ]);
        run_command(cmd, "Formatting volume")?;
        println!("[+] Volume formatted successfully!");

        // 2. Encrypt and write raw state file to Inode 16
        println!("[*] Encrypting and writing state to Inode 16...");
        let mut cmd = Command::new(&cocoonfs_bin);
        cmd.args(&[
            "-f",
            "--image", output_filename.to_str().unwrap(),
            "write-file",
            "--key", &secret_key_hex, // Pass key directly as a hex string!
            "--input-file", &args.state, // Input state file
            "16", // Positional <INODE-NUMBER>
            "0",  // Positional <INODE-FLAGS>
        ]);
        run_command(cmd, "Writing state to Inode 16")?;
        println!("[+] Staged and encrypted state file successfully!");

        // Temporary file paths for offline metadata injection
        let temp_route_file = PathBuf::from("./tmp_route.bin");
        let temp_nonce_file = PathBuf::from("./tmp_nonce.bin");

        // 3. Inject Routing & Identity Block under UUID_SECRET_STORAGE offline (inherently keyless)
        let kbs_path = args.resource_id.unwrap_or_else(|| "default/vtpm/state_key".to_string());
        println!("[*] Injecting routing block: '{}'...", kbs_path);
        fs::write(&temp_route_file, kbs_path.as_bytes())?;

        let mut cmd = Command::new(&cocoonfs_bin);
        cmd.args(&[
            "-f",
            "--image", output_filename.to_str().unwrap(),
            "aux-fs-metadata",
            "edit", // Access the nested edit subcommands
            "add-entry",
            UUID_SECRET_STORAGE,
            "--input-file", temp_route_file.to_str().unwrap(),
        ]);
        let route_res = run_command(cmd, "Injecting routing block");
        let _ = fs::remove_file(&temp_route_file); // Ensure cleanup
        route_res?;

        // 4. Inject 16-byte initial random boot nonce under UUID_SESSION_NONCE offline (inherently keyless)
        let mut initial_nonce = [0u8; 16];
        thread_rng().fill_bytes(&mut initial_nonce);
        let nonce_hex = hex::encode(initial_nonce);
        println!("[*] Injecting initial boot nonce: '{}'...", nonce_hex);
        fs::write(&temp_nonce_file, &initial_nonce)?;

        let mut cmd = Command::new(&cocoonfs_bin);
        cmd.args(&[
            "-f",
            "--image", output_filename.to_str().unwrap(),
            "aux-fs-metadata",
            "edit", // Access the nested edit subcommands
            "add-entry",
            UUID_SESSION_NONCE,
            "--input-file", temp_nonce_file.to_str().unwrap(),
        ]);
        let nonce_res = run_command(cmd, "Injecting initial session nonce");
        let _ = fs::remove_file(&temp_nonce_file); // Ensure cleanup
        nonce_res?;

        println!("\n[✓] SUCCESS: CocoonFS image initialized and secured!");
        println!("=====================================================================");

    } else {
        // ---------------------------------------------------------------------
        // LEGACY MODE: Encrypt raw state with AES-256-GCM and prefix legacy header
        // ---------------------------------------------------------------------
        println!("--- Preparing Legacy SVSMvTPM Raw Volume ---");
        let mut iv = [0u8; 12];
        thread_rng().fill_bytes(&mut iv);

        let mut payload = raw_vtpm_state.clone();
        let payload_size = payload.len() as u32;

        let key_array = GenericArray::from_slice(&secret_key);
        let cipher = Aes256Gcm::new(key_array);
        let nonce = Nonce::from_slice(&iv);

        let tag = cipher
            .encrypt_in_place_detached(nonce, b"", &mut payload)
            .map_err(|e| format!("Encryption failure: {:?}", e))?;

        let mut header = Vec::with_capacity(64);
        header.extend_from_slice(b"SVSMvTPM");
        header.extend_from_slice(&1u16.to_le_bytes());
        header.extend_from_slice(&1u16.to_le_bytes());
        header.extend_from_slice(&payload_size.to_le_bytes());
        header.extend_from_slice(&iv);
        header.extend_from_slice(tag.as_slice());
        header.extend_from_slice(&[0u8; 20]);

        assert_eq!(header.len(), 64, "Header must be exactly 64 bytes!");

        let mut final_image = Vec::new();
        final_image.extend_from_slice(&header);
        final_image.extend_from_slice(&payload);

        let current_size = final_image.len();
        let remainder = current_size % 4096;
        if remainder != 0 {
            let padding_needed = 4096 - remainder;
            final_image.extend(std::iter::repeat_n(0u8, padding_needed));
        }

        assert_eq!(final_image.len() % 4096, 0, "Image size must be a multiple of 4096!");

        let mut file = File::create(&output_filename)?;
        file.write_all(&final_image)?;

        println!("Success: Legacy image '{:?}' created successfully.", output_filename);
        println!("Payload size: {} bytes", payload_size);
        println!("Total image size (aligned to 4096): {} bytes", final_image.len());
    }

    Ok(())
}
