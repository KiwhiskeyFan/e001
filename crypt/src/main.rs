use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    Aes128Gcm, Nonce,
};
use generic_array::GenericArray;
use rand_core::RngCore;

const MAGIC: &[u8] = b"ENCR";
const KEY_BYTES: [u8; 16] = [42u8; 16]; // Hardcoded key (change to a secure key in practice)

fn main() -> io::Result<()> {
    println!("Enter the file name:");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let filename = input.trim();

    let path = Path::new(filename);
    if !path.exists() {
        eprintln!("File '{}' not found.", filename);
        return Ok(());
    }

    // Read the entire file into memory
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let key = GenericArray::from(KEY_BYTES);
    let cipher = Aes128Gcm::new(&key);

    let new_buffer: Vec<u8>;
    if buffer.starts_with(MAGIC) {
        // Decrypt
        println!("File detected as encrypted. Decrypting...");
        let iv_start = MAGIC.len();
        if buffer.len() < iv_start + 12 {
            eprintln!("Invalid encrypted file: too short.");
            return Ok(());
        }
        let iv_bytes = &buffer[iv_start..iv_start + 12];
        let ciphertext = &buffer[iv_start + 12..];
        let nonce = Nonce::from_slice(iv_bytes);
        match cipher.decrypt(nonce, Payload { msg: ciphertext, aad: b"" }) {
            Ok(plaintext) => new_buffer = plaintext,
            Err(e) => {
                eprintln!("Decryption failed: {}", e);
                return Ok(());
            }
        }
    } else {
        // Encrypt
        println!("File detected as plaintext. Encrypting...");
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        match cipher.encrypt(nonce, Payload { msg: &buffer, aad: b"" }) {
            Ok(ciphertext) => {
                new_buffer = [MAGIC.as_ref(), &nonce_bytes[..], &ciphertext[..]].concat();
            }
            Err(e) => {
                eprintln!("Encryption failed: {}", e);
                return Ok(());
            }
        }
    }

    // Overwrite the file with the new content
    let mut file = File::create(path)?;
    file.write_all(&new_buffer)?;

    if new_buffer.starts_with(MAGIC) {
        println!("File encrypted successfully.");
    } else {
        println!("File decrypted successfully.");
    }

    Ok(())
}