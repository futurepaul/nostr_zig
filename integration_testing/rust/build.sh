#!/bin/bash
set -e

echo "Building Rust NIP-44 reference implementation..."

# Copy Rust implementation from samples
cp -r ../../samples/nip44/rust/* .

# Create a wrapper binary that exposes functions for testing
cat > src/bin/nip44_wrapper.rs << 'EOF'
use nip44::{self, XChaCha20Poly1305};
use std::env;
use std::io::{self, Read};

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <command> [args...]", args[0]);
        return Ok(());
    }

    match args[1].as_str() {
        "conversation_key" => {
            let mut input = String::new();
            io::stdin().read_to_string(&mut input)?;
            let parts: Vec<&str> = input.trim().split_whitespace().collect();
            
            let sec1 = hex_to_bytes(parts[0]);
            let pub2 = hex_to_bytes(parts[1]);
            
            // Skip 0x02/0x03 prefix if present
            let pub2_key = if pub2.len() == 33 { &pub2[1..] } else { &pub2 };
            
            let conv_key = nip44::get_conversation_key(&sec1, pub2_key)?;
            println!("{}", bytes_to_hex(&conv_key));
        }
        "encrypt" => {
            let mut input = String::new();
            io::stdin().read_to_string(&mut input)?;
            let parts: Vec<&str> = input.trim().split_whitespace().collect();
            
            let sec1 = hex_to_bytes(parts[0]);
            let pub2 = hex_to_bytes(parts[1]);
            let plaintext = parts[2];
            
            let ciphertext = nip44::encrypt(&sec1, &pub2, plaintext)?;
            println!("{}", ciphertext);
        }
        "decrypt" => {
            let mut input = String::new();
            io::stdin().read_to_string(&mut input)?;
            let parts: Vec<&str> = input.trim().split_whitespace().collect();
            
            let sec1 = hex_to_bytes(parts[0]);
            let pub2 = hex_to_bytes(parts[1]);
            let payload = parts[2];
            
            let plaintext = nip44::decrypt(&sec1, &pub2, payload)?;
            println!("{}", plaintext);
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
        }
    }
    
    Ok(())
}
EOF

# Build the Rust implementation
cargo build --release --bin nip44_wrapper

echo "Rust implementation built successfully!"