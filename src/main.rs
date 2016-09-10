extern crate docopt;
extern crate ring;
extern crate rustc_serialize;
extern crate untrusted;

use ring::{rand, signature};
use docopt::Docopt;
use std::fs::File;
use std::io::{Read, Write};

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

const USAGE: &'static str = r#"
rustup signing tool

Usage:
  rust-sign <command> <key> [<file>]

Valid commands: generate, sign, verify.
"#;

#[derive(Debug, RustcDecodable)]
#[allow(non_snake_case)]
struct Args {
    arg_command: String,
    arg_key: String,
    arg_file: Option<String>,
}

fn generate(key_file_name: &str) {
    let rng = rand::SystemRandom::new();
    let (_, generated_bytes) = signature::Ed25519KeyPair::generate_serializable(&rng)
                                   .expect("failed to generate key");
    let mut out = File::create(key_file_name).expect("cannot open key file");
    out.write_all(&generated_bytes.private_key).expect("failed to write key bytes");
    out.write_all(&generated_bytes.public_key).expect("failed to write key bytes");
}

fn sign(key_file_name: &str, file: &str) {

    let mut key_file = File::open(key_file_name).expect("cannot open key file");
    let mut key_bytes = Vec::<u8>::new();
    key_file.read_to_end(&mut key_bytes).unwrap();
    let key_pair = signature::Ed25519KeyPair::from_bytes(&key_bytes[..32],
                                                         &key_bytes[32..])
                       .expect("failed to create key pair");
    
    let mut in_file = File::open(file).expect("cannot open file to be signed");
    let mut data = Vec::<u8>::new();
    in_file.read_to_end(&mut data).unwrap();
    let sig = key_pair.sign(&data);
    
    let name = format!("{}.sig.ed25519", &file);
    let mut out = File::create(name).expect("cannot open output file");
    out.write_all(sig.as_slice()).expect("failed to write signature");

}

fn verify(key_file_name: &str, file: &str) {

    let mut key_file = File::open(key_file_name).expect("cannot open key file");
    let mut key_bytes = Vec::<u8>::new();
    key_file.read_to_end(&mut key_bytes).unwrap();
    let public_key = if key_bytes.len() == 64 {
            untrusted::Input::from(&key_bytes[32..])
        } else {
            untrusted::Input::from(&key_bytes)
        };

    let mut in_file = File::open(file).expect("cannot open file to be verified");
    let mut data = Vec::<u8>::new();
    in_file.read_to_end(&mut data).unwrap();
    let msg = untrusted::Input::from(&data);

    let sig_file_name = format!("{}.sig.ed25519", &file);
    let mut sig_file = File::open(&sig_file_name).expect("cannot open signature file");
    let mut sig_bytes = Vec::<u8>::new();
    sig_file.read_to_end(&mut sig_bytes).unwrap();
    let sig = untrusted::Input::from(&sig_bytes);
    
    let res = signature::verify(&signature::ED25519, public_key, msg, sig);
    if res.is_ok() {
        println!("signature ok");
    } else {
        println!("signature incorrect");
    }

}

fn main() {
    let args: Args = Docopt::new(USAGE)
                         .and_then(|d| d.version(Some(VERSION.to_string())).decode())
                         .unwrap_or_else(|e| e.exit());
    if args.arg_command == "generate" {
        generate(&args.arg_key);
    } else if args.arg_command == "sign" {
        sign(&args.arg_key, &args.arg_file.unwrap());
    } else if args.arg_command == "verify" {
        verify(&args.arg_key, &args.arg_file.unwrap());
    }
}
