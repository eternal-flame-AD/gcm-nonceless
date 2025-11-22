#![allow(deprecated)]
use std::io::{Read, Write};

use aes::cipher::{
    ArrayLength, BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit, KeySizeUser,
    StreamCipher, consts::U16, generic_array::GenericArray,
};
use clap::{Parser, ValueEnum};
use gcm_nonceless::{extract_nonce, instantiate_keystream, recover_counter};

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    key: String,

    #[arg(short, long, default_value = "-")]
    input: String,

    #[arg(short, long, default_value = "aes-256", help = "Cipher to use")]
    cipher: CipherOption,

    #[arg(short, long, help = "Associated data in hex")]
    aad: Option<String>,

    #[arg(short, long, help = "Detached authentication tag in hex")]
    tag: Option<String>,

    #[arg(long)]
    non_standard_nonce: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum CipherOption {
    #[value(name = "aes-128")]
    Aes128,
    #[value(name = "aes-256")]
    Aes256,
}

const fn decode_hex_nibble(nibble: u8) -> Option<u8> {
    let res = if nibble >= b'a' {
        nibble - b'a' + 10
    } else if nibble >= b'A' {
        nibble - b'A' + 10
    } else {
        nibble - b'0'
    };
    if res < 16 { Some(res) } else { None }
}

fn decode_param<L: ArrayLength<u8>>(name: &'static str, data: &str) -> GenericArray<u8, L> {
    if data.len() == L::to_usize() {
        GenericArray::from_slice(data.as_bytes()).clone()
    } else if data.len() == L::to_usize() * 2 {
        let mut output = GenericArray::<u8, L>::default();
        for (i, byte) in data.as_bytes().chunks_exact(2).enumerate() {
            let high_nibble = decode_hex_nibble(byte[0]).expect("Invalid hex nibble");
            let low_nibble = decode_hex_nibble(byte[1]).expect("Invalid hex nibble");
            output[i] = (high_nibble << 4) | low_nibble;
        }
        output
    } else {
        panic!(
            "{} must be {} bytes long or {} hex digits",
            name,
            L::to_usize(),
            L::to_usize() * 2
        );
    }
}

fn run<C: BlockCipher + BlockEncrypt + BlockDecrypt + BlockSizeUser<BlockSize = U16> + KeyInit>(
    args: Args,
    aad: &[u8],
    mut c: Vec<u8>,
) {
    let key: GenericArray<u8, <C as KeySizeUser>::KeySize> = decode_param("key", &args.key);
    let tag = args.tag.map(|t| decode_param("tag", &t));
    let cipher = C::new(&key);
    let recovered_j0 = recover_counter(&cipher, &c, tag.as_ref(), &aad);
    if !args.non_standard_nonce {
        let nonce = extract_nonce::<C>(&recovered_j0)
            .expect("Extracted nonce invalid. Wrong input or forgot --non-standard-nonce?");
        let nonce_hex = hex::encode(nonce);
        eprintln!("Recovered nonce: {nonce_hex}");
    } else {
        let nonce_hex = hex::encode(recovered_j0);
        eprintln!("Recovered IV: {nonce_hex}");
    }
    if tag.is_none() {
        c.truncate(c.len() - 16);
    }

    let mut decryptor = instantiate_keystream(cipher, &recovered_j0);

    let mut stdout = std::io::stdout();

    c.chunks_mut(1024).for_each(|block| {
        decryptor.apply_keystream(block);
        stdout.write_all(block).expect("Failed to write to stdout");
    });
}

fn main() {
    let mut args = Args::parse();
    let mut data = Vec::new();
    let aad = args
        .aad
        .as_mut()
        .map(|a| hex::decode(a).expect("Invalid hex in associated data"))
        .unwrap_or_default();

    if args.input == "-" {
        std::io::stdin()
            .read_to_end(&mut data)
            .expect("Failed to read from stdin");
    } else {
        std::fs::File::open(&args.input)
            .expect("Failed to open file")
            .read_to_end(&mut data)
            .expect("Failed to read from file");
    };
    match args.cipher {
        CipherOption::Aes128 => {
            run::<aes::Aes128>(args, &aad, data);
        }
        CipherOption::Aes256 => {
            run::<aes::Aes256>(args, &aad, data);
        }
    }
}
