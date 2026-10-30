mod auth;
mod ftp;
mod keygen;
mod self_test;

use std::path::PathBuf;
use std::sync::Arc;
use auth::{AuthManager, AuthorizedKey};
use ftp::FtpServer;
use keygen::KeyPair1024;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--test" || a == "-t") {
        println!("================================================================================");
        println!("MAHAJANI: RUNTIME & SECURITY HARDENING VERIFICATION (13 GATES)");
        println!("================================================================================");
        self_test::run_self_test();
        return;
    }

    let bind_addr = args.iter().position(|a| a == "--addr")
        .and_then(|idx| args.get(idx + 1))
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:2121".to_string());

    let keys_dir = PathBuf::from("./authorized_keys");
    let root_dir = PathBuf::from("./ftp_data");

    let auth_manager = AuthManager::new(&keys_dir);

    // If no keys exist, generate a default alice 1024-bit key
    if !auth_manager.has_user("alice") {
        println!("[SETUP] Generating default 1024-bit authorized keypair for 'alice'...");
        let pair = KeyPair1024::generate();
        auth_manager.register_key("alice", AuthorizedKey::Rsa1024(pair.verifying_key));
        println!("[SETUP] Registered 'alice' with 1024-bit RSA key");
    }

    let auth_arc = Arc::new(auth_manager);
    let server = FtpServer::new(&bind_addr, auth_arc, root_dir);

    println!("[STARTUP] Starting Mahajani Server on {}", bind_addr);
    if let Err(e) = server.run() {
        eprintln!("[FATAL] Server error: {}", e);
    }
}
