## vtpm-to-svsm-blk
This tool
1. encrypts the vTPM state file generated using the official TCG simulator using aes256gcm cipher.
2. creates a disk image by joining a suitable header and the encrypted payload.

The header is 64 bytes long, consisting of
- magic (8 bytes),
- version (2 bytes),
- CipherID (2 bytes),
- payload size (4 bytes),
- IV (12 bytes),
- authentication tag (16 bytes),
- and reserved (20 bytes).

The output disk image file can be consumed by SVSM. During boot, a successful attestation will provide the SVSM with the encryption key.
This key will be used to decrypt the image attached as virtio-blk, so that the vTPM state file persists across reboots.

This project is only part of a POC. Eventually we will be using the [cocoonfs image](https://coconut-svsm.github.io/cocoon-tpm/cocoonfs/cocoonfs-format.html)
instead of the self constructed raw disk image.

## Prerequisite
- Run the [TPM provisioner](https://github.com/armenon-rh/tpm_provisioner) utility and obtain a vTPM state file.
- Create a random key of size 32 bytes
```bash
openssl rand -out key.bin 32
```

## Build and Run
cargo build
cargo run -- -k <key.bin> -s <vTPM-state-file> -o </path/to/out/dir>

The output directory will have a "vtpm_state.img" disk image.
This image can be used to [attach](https://github.com/coconut-svsm/svsm/compare/main...armenon-rh:svsm:attestation_kbs) to the SVSM and provide a permanent state.
