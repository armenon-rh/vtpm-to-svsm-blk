# Developer Guide: CocoonFS Integration in `vtpm-to-svsm-blk`

This guide explains the architecture, design, and Rust semantics used to
implement the CocoonFS-based state encryption and image generation inside the
`vtpm-to-svsm-blk` host tool.

---

## 1. Architectural Overview

The `vtpm-to-svsm-blk` tool runs purely on **standard Linux** (Host space).

While SVSM (which runs in `no_std` on bare-metal with no OS shell) *must* link
directly to the CocoonFS library, the host-space admin tool does not share this
constraint. Therefore, we utilize the **Decoupled Process Spawning** approach to
drive the compiled `cocoonfs` command-line utility.

---

## 2. Formatting and Writing the Encrypted State
We spawn the compiled `cocoonfs` CLI to format the volume and write the state file into Inode 16.

```rust
let status = Command::new(&cocoonfs_bin)
    .args(&[
        "-f", // Force raw sector layout (128-byte alignment)
        "--image", output_filename.to_str().unwrap(),
        "mkfs",
        "--key", &secret_key_hex, // Pass key directly as a hex string!
        "--cipher", "aes",
        "--hash-family", "sha2",
        "--target-security-strength", "256",
        "--salt", "01010101010101010101010101010101", // Standard 16-byte hex salt
        "--image-size", "10M", // Explicitly specify 10MB image size to format
        "--aux-fs-metadata-extra-reserve-capacity", "1024", // Pre-allocate 1KB reserve
    ])
    .status()?;
```

---

## 3. Keyless Offline Metadata Injection (Routing & Nonces)
To allow SVSM to dynamically route its requests and protect against rollback
replays, we inject
1. the KBS Resource ID (Routing UUID) and
2. an initial boot session nonce (Nonce UUID) into the unencrypted auxiliary
metadata region of the header:

```rust
let nonce_hex = hex::encode(initial_nonce);
let status = Command::new(&cocoonfs_bin)
    .args(&[
        "-f",
        "--image", output_filename.to_str().unwrap(),
        "aux-fs-metadata",
        "edit",
        "add-entry",
        UUID_SESSION_NONCE,
        "--input-file", temp_nonce_file.to_str().unwrap(),
    ])
    .status()?;
```
* **`hex::encode`:** Formats our raw 16-byte random array into a 32-character
hexadecimal ASCII string, which is the exact format CocoonFS expects for its raw
binary metadata payloads.

---

## 4. How to Run the Project & Build Images

Follow these exact steps to compile and execute the tool with an external key
file and custom VM ID on Linux.

### Step A: Ensure CocoonFS is Compiled
This tool requires the `cocoonfs` CLI to be compiled first. Run:
```bash
cd ../
git clone https://github.com/coconut-svsm/cocoon-tpm.git
cd cocoon-tpm
cargo build -p cocoonfs-cli
```
This builds the binary under `../cocoon-tpm/target/debug/cocoonfs` which
`vtpm-to-svsm-blk` auto-detects dynamically!

---
### Step B: Create a 32-Byte Key File
The CocoonFS volume requires a 256-bit symmetric key. Generate a random
32-character hexadecimal key file (representing 16 raw bytes of entropy) using OpenSSL:
```bash
# This creates a file containing exactly 32 raw bytes representing a 256-bit key
openssl rand -hex 16 | tr -d '\n' > key_file.bin
```

---
### Step C: Generate a Unique VM ID / KBS Resource ID
To uniquely register the virtual machine inside the KBS database, generate a
standard UUID using `uuidgen` and construct a KBS path:
```bash
# Generate a fresh UUID and clean up trailing newlines
UUID_VAL=$(uuidgen | tr -d '\n')

# This unique path (e.g. "default/vtpm/4c8bc238-...") acts as our VM Resource ID
VM_RESOURCE_ID="default/vtpm/$UUID_VAL"
echo "Generated VM Resource ID: $VM_RESOURCE_ID"
```

---

### Step D: Create Output Folder and Run the Tool
Create a dedicated folder for your secure images, and run `vtpm-to-svsm-blk`
passing your key file, raw state file, and the unique VM Resource ID:

```bash
# 1. Create a dedicated output directory
mkdir -p artefact/

# 2. Execute the tool in CocoonFS mode (-c)
cargo run -- \
  -c \
  -k key_file.bin \
  -s ../tpm_provisioner/artefacts/state.bin \
  -r "$VM_RESOURCE_ID" \
  -o artefact/
```

### Behind the Scenes of this Command:
1. `vtpm-to-svsm-blk` pre-allocates a 10MB blank disk image `artefact/vtpm_state.img`.
2. It auto-detects `../cocoon-tpm/target/debug/cocoonfs` and calls `mkfs` to
   format the disk using your key.
3. It encrypts and stages your `state.bin` securely into Inode 16.
4. It offline-injects the unique VM Resource ID (`default/vtpm/...`)
   under UUID `bc27ddb0-0b61-4fa3-979a-ca81f4a476bc`.
5. It offline-injects a fresh random 16-byte initial boot session nonce
   under UUID `aabbccdd-1122-3344-5566-77889900aabb`.
6. **Output Image:** The finalized `artefact/vtpm_state.img` (10MB virtual disk)
   is fully secured and ready to attach to SVSM as a QEMU `virtio-blk` drive!
