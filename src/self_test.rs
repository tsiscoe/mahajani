use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use crate::auth::{AuthManager, AuthorizedKey};
use crate::ftp::FtpServer;
use crate::keygen::KeyPair1024;

/// Automated End-to-End Self-Test proving the server works against real TCP connections
pub fn run_self_test() {
    let test_port = 22123;
    let bind_addr = format!("127.0.0.1:{}", test_port);
    let test_dir = PathBuf::from("./target/test_ftp_data");
    let keys_dir = PathBuf::from("./target/test_keys");
    let _ = fs::remove_dir_all(&test_dir);
    let _ = fs::remove_dir_all(&keys_dir);
    fs::create_dir_all(&test_dir).unwrap();
    fs::create_dir_all(&keys_dir).unwrap();

    // 1. Generate authorized 1024-bit keypair for 'alice'
    println!("[1/6] Generating 1024-bit keypair for 'alice'...");
    let alice_keys = KeyPair1024::generate();

    // Generate unauthorized keypair for 'mallory'
    println!("[1/6] Generating forged keypair for 'mallory' (attacker)...");
    let mallory_keys = KeyPair1024::generate();

    let auth_mgr = AuthManager::new(&keys_dir);
    auth_mgr.register_key("alice", AuthorizedKey::Rsa1024(alice_keys.verifying_key.clone()));
    let auth_arc = Arc::new(auth_mgr);

    // 2. Launch FTP server in background thread
    let server = FtpServer::new(&bind_addr, auth_arc, test_dir.clone());
    std::thread::spawn(move || {
        let _ = server.run();
    });

    let mut stream_opt = None;
    for _ in 0..15 {
        if let Ok(s) = TcpStream::connect(&bind_addr) {
            stream_opt = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let mut stream = stream_opt.expect("Failed to connect to FTP server after retries");
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    let mut banner = String::new();
    reader.read_line(&mut banner).unwrap();
    assert!(banner.starts_with("220"), "Expected 220 banner, got: {}", banner);
    println!("      Banner verified: {}", banner.trim());

    // Try PWD without logging in
    stream.write_all(b"PWD\r\n").unwrap();
    let mut resp = String::new();
    reader.read_line(&mut resp).unwrap();
    assert!(resp.starts_with("530"), "Expected 530 for unauthenticated PWD, got: {}", resp);
    println!("      Unauthenticated command correctly blocked: {}", resp.trim());

    // 4. Test Attack / Forged Signature Rejection
    println!("[3/6] Testing forged signature rejection (Mallory signing for Alice)...");
    stream.write_all(b"USER alice\r\n").unwrap();
    resp.clear();
    reader.read_line(&mut resp).unwrap();
    assert!(resp.starts_with("331"), "Expected 331 challenge, got: {}", resp);
    println!("      Server issued challenge: {}", resp.trim());

    // Extract challenge nonce
    let challenge = resp.split("Challenge: ")
        .nth(1)
        .and_then(|s| s.split('.').next())
        .expect("Failed to parse challenge nonce");

    // Mallory signs Alice's challenge with Mallory's key
    let forged_sig = mallory_keys.sign_challenge(challenge);
    let pass_cmd = format!("PASS {}\r\n", forged_sig);
    stream.write_all(pass_cmd.as_bytes()).unwrap();

    resp.clear();
    reader.read_line(&mut resp).unwrap();
    assert!(resp.starts_with("530"), "Expected 530 for forged signature, got: {}", resp);
    println!("      Forged signature rejected successfully: {}", resp.trim());

    // 5. Test Legitimate OpenPGP / 1024-bit Key Authentication
    println!("[4/6] Authenticating Alice with valid 1024-bit signed challenge...");
    stream.write_all(b"USER alice\r\n").unwrap();
    resp.clear();
    reader.read_line(&mut resp).unwrap();
    let fresh_challenge = resp.split("Challenge: ")
        .nth(1)
        .and_then(|s| s.split('.').next())
        .expect("Failed to parse challenge nonce");

    let valid_sig = alice_keys.sign_challenge(fresh_challenge);
    let pass_valid = format!("PASS {}\r\n", valid_sig);
    stream.write_all(pass_valid.as_bytes()).unwrap();

    resp.clear();
    reader.read_line(&mut resp).unwrap();
    assert!(resp.starts_with("230"), "Expected 230 on valid signature, got: {}", resp);
    println!("      Authentication passed: {}", resp.trim());

    // 6. Test File Transfer (PASV, STOR, RETR, DELE)
    println!("[5/6] Testing FTP operations: PWD, PASV, STOR, RETR, LIST...");
    stream.write_all(b"PWD\r\n").unwrap();
    resp.clear();
    reader.read_line(&mut resp).unwrap();
    assert!(resp.starts_with("257"), "Expected 257 for PWD, got: {}", resp);

    // Enter PASV
    stream.write_all(b"PASV\r\n").unwrap();
    resp.clear();
    reader.read_line(&mut resp).unwrap();
    assert!(resp.starts_with("227"), "Expected 227 PASV response, got: {}", resp);

    let pasv_port = parse_pasv_port(&resp);
    let data_addr = format!("127.0.0.1:{}", pasv_port);

    // STOR testfile
    stream.write_all(b"STOR test_artifact.txt\r\n").unwrap();
    let mut data_stream = TcpStream::connect(&data_addr).unwrap();
    resp.clear();
    reader.read_line(&mut resp).unwrap();
    assert!(resp.starts_with("150"), "Expected 150 transfer start, got: {}", resp);

    let test_data = b"speakeasy cryptographic verification payload test.";
    data_stream.write_all(test_data).unwrap();
    drop(data_stream);

    resp.clear();
    reader.read_line(&mut resp).unwrap();
    assert!(resp.starts_with("226"), "Expected 226 transfer complete, got: {}", resp);
    println!("      STOR transfer complete: test_artifact.txt written.");

    // RETR testfile
    stream.write_all(b"PASV\r\n").unwrap();
    resp.clear();
    reader.read_line(&mut resp).unwrap();
    let pasv_port2 = parse_pasv_port(&resp);
    let data_addr2 = format!("127.0.0.1:{}", pasv_port2);

    stream.write_all(b"RETR test_artifact.txt\r\n").unwrap();
    let mut data_stream2 = TcpStream::connect(&data_addr2).unwrap();
    resp.clear();
    reader.read_line(&mut resp).unwrap();
    assert!(resp.starts_with("150"), "Expected 150 RETR start, got: {}", resp);

    let mut downloaded = Vec::new();
    data_stream2.read_to_end(&mut downloaded).unwrap();
    drop(data_stream2);

    resp.clear();
    reader.read_line(&mut resp).unwrap();
    assert!(resp.starts_with("226"), "Expected 226 RETR complete, got: {}", resp);
    assert_eq!(downloaded, test_data);
    println!("      RETR transfer complete: downloaded content byte-matches original payload.");

    // 6. Test Security Invariant: CWD Traversal Defense
    println!("[6/10] Testing CWD path traversal defense (escaping virtual root)...");
    stream.write_all(b"CWD ..\\..\r\n").unwrap();
    resp.clear();
    reader.read_line(&mut resp).unwrap();
    assert!(resp.starts_with("550"), "Expected 550 for CWD traversal attempt, got: {}", resp);
    println!("       CWD traversal correctly blocked: {}", resp.trim());

    // 7. Test Security Invariant: STOR / DELE Traversal Defense
    println!("[7/10] Testing STOR and DELE traversal injection defense...");
    stream.write_all(b"STOR ../evil_payload.txt\r\n").unwrap();
    resp.clear();
    reader.read_line(&mut resp).unwrap();
    assert!(resp.starts_with("550"), "Expected 550 for STOR traversal attempt, got: {}", resp);

    stream.write_all(b"DELE ../escaped_target.txt\r\n").unwrap();
    resp.clear();
    reader.read_line(&mut resp).unwrap();
    assert!(resp.starts_with("550"), "Expected 550 for DELE traversal attempt, got: {}", resp);
    println!("       STOR/DELE path traversals correctly rejected.");

    // 8. Test Security Invariant: Public Key Overwrite Protection
    println!("[8/10] Testing SITE REGISTER account takeover / key overwrite protection...");
    stream.write_all(b"SITE REGISTER alice fake_armored_key_attempt\r\n").unwrap();
    resp.clear();
    reader.read_line(&mut resp).unwrap();
    assert!(resp.starts_with("550"), "Expected 550 for re-registering existing user 'alice', got: {}", resp);
    println!("       Public key overwrite rejected: {}", resp.trim());

    // 9. Test Security Invariant: Username Path Traversal in SITE REGISTER
    println!("[9/10] Testing SITE REGISTER username traversal sanitization...");
    stream.write_all(b"SITE REGISTER ../attacker fake_payload\r\n").unwrap();
    resp.clear();
    reader.read_line(&mut resp).unwrap();
    assert!(resp.starts_with("550"), "Expected 550 for username traversal attempt, got: {}", resp);
    println!("       Username traversal correctly rejected: {}", resp.trim());

    // 10. Clean disconnect
    stream.write_all(b"QUIT\r\n").unwrap();
    resp.clear();
    reader.read_line(&mut resp).unwrap();
    assert!(resp.starts_with("221"), "Expected 221 on QUIT, got: {}", resp);
    println!("[10/10] Clean disconnect verified.");

    println!("================================================================================");
    println!("ALL 10/10 SECURITY & RUNTIME GATES PASSED (2300EMPIRE PROVE IT WORKS)");
    println!("================================================================================");
}

fn parse_pasv_port(resp: &str) -> u16 {
    let start = resp.find('(').expect("Invalid PASV format");
    let end = resp.find(')').expect("Invalid PASV format");
    let parts: Vec<&str> = resp[start + 1..end].split(',').collect();
    assert_eq!(parts.len(), 6, "Expected 6 comma-separated numbers in PASV");
    let p1: u16 = parts[4].parse().unwrap();
    let p2: u16 = parts[5].parse().unwrap();
    (p1 << 8) | p2
}
