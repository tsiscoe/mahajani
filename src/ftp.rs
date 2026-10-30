use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use crate::auth::AuthManager;

pub struct FtpServer {
    bind_addr: String,
    auth_manager: Arc<AuthManager>,
    root_dir: PathBuf,
    max_connections: usize,
    active_connections: Arc<AtomicUsize>,
}

struct ConnectionGuard(Arc<AtomicUsize>);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl FtpServer {
    pub fn new(bind_addr: &str, auth_manager: Arc<AuthManager>, root_dir: PathBuf) -> Self {
        fs::create_dir_all(&root_dir).ok();
        Self {
            bind_addr: bind_addr.to_string(),
            auth_manager,
            root_dir,
            max_connections: 64,
            active_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(&self.bind_addr)?;
        println!("[FTP] speakeasy Server listening on {}", self.bind_addr);
        println!("[FTP] Virtual Root: {:?}", self.root_dir);

        for stream_res in listener.incoming() {
            match stream_res {
                Ok(stream) => {
                    let active = self.active_connections.fetch_add(1, Ordering::SeqCst);
                    if active >= self.max_connections {
                        self.active_connections.fetch_sub(1, Ordering::SeqCst);
                        let mut s = stream;
                        let _ = s.write_all(b"421 Service busy: Maximum concurrent connections reached.\r\n");
                        let _ = s.flush();
                        continue;
                    }

                    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

                    let auth_clone = Arc::clone(&self.auth_manager);
                    let root_clone = self.root_dir.clone();
                    let counter_clone = Arc::clone(&self.active_connections);
                    std::thread::spawn(move || {
                        let _guard = ConnectionGuard(counter_clone);
                        let mut session = FtpSession::new(stream, auth_clone, root_clone);
                        session.handle();
                    });
                }
                Err(e) => {
                    eprintln!("[FTP] Connection accept error: {}", e);
                }
            }
        }
        Ok(())
    }
}

/// Canonical path resolution strictly preventing escaping the virtual root.
/// Returns (normalized_relative_path, absolute_filesystem_path) on success.
fn resolve_safe_path(root: &Path, rel: &Path, user_input: &str) -> Result<(PathBuf, PathBuf), ()> {
    // 1. Immediately reject drive letters, absolute slashes, or null bytes
    if user_input.contains(':')
        || user_input.starts_with('/')
        || user_input.starts_with('\\')
        || user_input.contains('\0')
    {
        return Err(());
    }

    // 2. Normalization walk
    let mut normalized = rel.to_path_buf();
    for part in user_input.split(['/', '\\']) {
        if part.is_empty() || part == "." {
            continue;
        } else if part == ".." {
            if !normalized.pop() {
                return Err(()); // Attempted to escape above virtual root
            }
        } else {
            normalized.push(part);
        }
    }

    let full_path = root.join(&normalized);

    // 3. Verify canonical path stays within canonical root
    if let Ok(root_canon) = root.canonicalize() {
        if full_path.exists() {
            if let Ok(full_canon) = full_path.canonicalize() {
                if !full_canon.starts_with(&root_canon) {
                    return Err(());
                }
            }
        } else if let Some(parent) = full_path.parent() {
            if parent.exists() {
                if let Ok(parent_canon) = parent.canonicalize() {
                    if !parent_canon.starts_with(&root_canon) {
                        return Err(());
                    }
                }
            }
        }
    }

    Ok((normalized, full_path))
}

/// Read a line with an explicit byte ceiling to prevent memory exhaustion DoS attacks
fn read_line_capped<R: BufRead>(reader: &mut R, buf: &mut String, max_bytes: usize) -> std::io::Result<usize> {
    let mut total = 0;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(total);
        }
        let (done, used) = match available.iter().position(|&b| b == b'\n') {
            Some(pos) => (true, pos + 1),
            None => (false, available.len()),
        };
        if total + used > max_bytes {
            reader.consume(used);
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Line buffer limit exceeded"));
        }
        let s = std::str::from_utf8(&available[..used])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        buf.push_str(s);
        reader.consume(used);
        total += used;
        if done {
            return Ok(total);
        }
    }
}

struct FtpSession {
    stream: TcpStream,
    auth_manager: Arc<AuthManager>,
    root_dir: PathBuf,
    current_rel_dir: PathBuf,
    session_id: String,
    username: Option<String>,
    authenticated: bool,
    data_listener: Option<TcpListener>,
}

impl FtpSession {
    fn new(stream: TcpStream, auth_manager: Arc<AuthManager>, root_dir: PathBuf) -> Self {
        let session_id = format!("sess_{:x}", rand::random::<u64>());
        Self {
            stream,
            auth_manager,
            root_dir,
            current_rel_dir: PathBuf::from(""),
            session_id,
            username: None,
            authenticated: false,
            data_listener: None,
        }
    }

    fn send_resp(&mut self, code: u32, msg: &str) {
        let line = format!("{} {}\r\n", code, msg);
        let _ = self.stream.write_all(line.as_bytes());
        let _ = self.stream.flush();
    }

    fn handle(&mut self) {
        let peer_addr = self.stream.peer_addr().ok();
        println!("[FTP][{}] Client connected from {:?}", self.session_id, peer_addr);

        self.send_resp(220, "speakeasy OpenPGP FTP Server ready.");

        let reader_stream = match self.stream.try_clone() {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut reader = BufReader::new(reader_stream);
        let mut line = String::new();

        loop {
            line.clear();
            match read_line_capped(&mut reader, &mut line, 4096) {
                Ok(0) => break, // EOF / disconnected
                Ok(_) => {
                    let trimmed = line.trim_end_matches(|c| c == '\r' || c == '\n').trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if !self.process_command(trimmed) {
                        break; // QUIT or fatal
                    }
                }
                Err(_) => {
                    self.send_resp(500, "Command line exceeded buffer ceiling (4096 bytes).");
                    break;
                }
            }
        }
        println!("[FTP][{}] Client disconnected", self.session_id);
    }

    fn process_command(&mut self, cmd_line: &str) -> bool {
        let (cmd, args) = match cmd_line.split_once(' ') {
            Some((c, a)) => (c.to_uppercase(), a.trim()),
            None => (cmd_line.to_uppercase(), ""),
        };

        match cmd.as_str() {
            "USER" => {
                if args.is_empty() {
                    self.send_resp(501, "Syntax error in parameters: USER <username>");
                    return true;
                }
                let uname = args.to_string();
                if !self.auth_manager.has_user(&uname) {
                    self.send_resp(530, &format!("User '{}' not found in OpenPGP authorized registry", uname));
                    return true;
                }
                let challenge = self.auth_manager.issue_challenge(&self.session_id);
                self.username = Some(uname);
                self.authenticated = false;
                self.send_resp(331, &format!("Challenge: {}. Sign with OpenPGP key and submit in PASS.", challenge));
            }
            "PASS" => {
                let uname = match &self.username {
                    Some(u) => u.clone(),
                    None => {
                        self.send_resp(503, "Login with USER first.");
                        return true;
                    }
                };

                if args.is_empty() {
                    self.send_resp(501, "Syntax error in parameters: PASS <signature>");
                    return true;
                }

                match self.auth_manager.verify_signature(&self.session_id, &uname, args) {
                    Ok(()) => {
                        self.authenticated = true;
                        println!("[FTP][{}] OpenPGP authentication SUCCESS for user '{}'", self.session_id, uname);
                        self.send_resp(230, "OpenPGP authentication successful. Welcome!");
                    }
                    Err(err) => {
                        self.authenticated = false;
                        eprintln!("[FTP][{}] OpenPGP auth FAILED for user '{}': {}", self.session_id, uname, err);
                        self.send_resp(530, &format!("Authentication failed: {}", err));
                    }
                }
            }
            "QUIT" => {
                self.send_resp(221, "Goodbye.");
                return false;
            }
            "SYST" => {
                self.send_resp(215, "UNIX Type: L8 (speakeasy Core)");
            }
            "FEAT" => {
                let feat_resp = "211-Features:\r\n UTF8\r\n PASV\r\n REST STREAM\r\n SITE REGISTER\r\n211 End\r\n";
                let _ = self.stream.write_all(feat_resp.as_bytes());
                let _ = self.stream.flush();
            }
            "TYPE" => {
                self.send_resp(200, "Type set to I.");
            }
            "NOOP" => {
                self.send_resp(200, "NOOP OK.");
            }
            "SITE" => {
                let parts: Vec<&str> = args.splitn(3, ' ').collect();
                if parts.is_empty() || parts[0].is_empty() {
                    self.send_resp(501, "Syntax error: SITE <SUBCOMMAND> <ARGS>");
                    return true;
                }
                match parts[0].to_uppercase().as_str() {
                    "REGISTER" | "PUBKEY" => {
                        if parts.len() < 3 {
                            self.send_resp(501, "Syntax error: SITE REGISTER <username> <ascii_armored_pubkey_or_base64>");
                            return true;
                        }
                        let uname = parts[1];
                        let key_payload = parts[2];
                        match self.auth_manager.register_pubkey_content(uname, key_payload) {
                            Ok(()) => {
                                self.send_resp(200, &format!("Public key registered for user '{}'.", uname));
                            }
                            Err(e) => {
                                eprintln!("[SECURITY BREACH][REGISTRATION] Session {} registration rejected: {}", self.session_id, e);
                                self.send_resp(550, &format!("Registration failed: {}", e));
                            }
                        }
                    }
                    "HELP" => {
                        self.send_resp(214, "SITE commands: SITE REGISTER <username> <armored_pubkey_or_base64>");
                    }
                    _ => {
                        self.send_resp(504, "Unknown SITE command.");
                    }
                }
            }
            // All subsequent commands require valid OpenPGP authentication
            _ if !self.authenticated => {
                self.send_resp(530, "Please login with USER and OpenPGP signed PASS.");
            }
            "PWD" => {
                let display = format!("/{}", self.current_rel_dir.to_string_lossy().replace('\\', "/"));
                self.send_resp(257, &format!("\"{}\" is current directory.", display));
            }
            "CWD" => {
                if args == "/" || args == "~" {
                    self.current_rel_dir = PathBuf::new();
                    self.send_resp(250, "Directory successfully changed.");
                } else {
                    match resolve_safe_path(&self.root_dir, &self.current_rel_dir, args) {
                        Ok((rel_norm, abs_path)) => {
                            if abs_path.is_dir() {
                                self.current_rel_dir = rel_norm;
                                self.send_resp(250, "Directory successfully changed.");
                            } else {
                                self.send_resp(550, "Failed to change directory: Not a directory.");
                            }
                        }
                        Err(()) => {
                            eprintln!("[SECURITY BREACH][TRAVERSAL] Session {} attempted CWD traversal: '{}'", self.session_id, args);
                            self.send_resp(550, "Security violation: Traversal attempt logged and rejected.");
                        }
                    }
                }
            }
            "PASV" => {
                let listener = match TcpListener::bind("127.0.0.1:0") {
                    Ok(l) => l,
                    Err(e) => {
                        self.send_resp(425, &format!("Can't open data connection: {}", e));
                        return true;
                    }
                };
                let port = match listener.local_addr() {
                    Ok(addr) => addr.port(),
                    Err(_) => {
                        self.send_resp(425, "Failed to get local port");
                        return true;
                    }
                };

                self.data_listener = Some(listener);
                let p1 = port >> 8;
                let p2 = port & 0xFF;
                self.send_resp(227, &format!("Entering Passive Mode (127,0,0,1,{},{}).", p1, p2));
            }
            "LIST" => {
                let mut data_stream = match self.accept_data_connection() {
                    Some(s) => s,
                    None => return true,
                };

                self.send_resp(150, "Here comes the directory listing.");

                let target_dir = self.root_dir.join(&self.current_rel_dir);
                let mut listing = String::new();

                if let Ok(entries) = fs::read_dir(target_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        let filename = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
                        let metadata = entry.metadata().ok();
                        let is_dir = metadata.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                        let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
                        let type_char = if is_dir { 'd' } else { '-' };

                        listing.push_str(&format!(
                            "{}rw-r--r-- 1 owner group {:10} Oct 16 12:00 {}\r\n",
                            type_char, size, filename
                        ));
                    }
                }

                let _ = data_stream.write_all(listing.as_bytes());
                drop(data_stream);
                self.send_resp(226, "Directory send OK.");
            }
            "RETR" => {
                if args.is_empty() {
                    self.send_resp(501, "Syntax error in parameters: RETR <filename>");
                    return true;
                }
                let filepath = match resolve_safe_path(&self.root_dir, &self.current_rel_dir, args) {
                    Ok((_, p)) => p,
                    Err(()) => {
                        eprintln!("[SECURITY BREACH][RECON/TRAVERSAL] Session {} attempted unauthorized RETR traversal: '{}'", self.session_id, args);
                        self.send_resp(550, "Security violation: Traversal attempt logged and rejected.");
                        return true;
                    }
                };

                if !filepath.exists() || filepath.is_dir() {
                    self.send_resp(550, "File not found.");
                    return true;
                }

                let mut data_stream = match self.accept_data_connection() {
                    Some(s) => s,
                    None => return true,
                };

                self.send_resp(150, &format!("Opening BINARY mode data connection for {}.", args));

                match File::open(&filepath) {
                    Ok(mut f) => {
                        let mut buf = [0u8; 8192];
                        loop {
                            match f.read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => {
                                    if data_stream.write_all(&buf[..n]).is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        drop(data_stream);
                        self.send_resp(226, "Transfer complete.");
                    }
                    Err(e) => {
                        drop(data_stream);
                        self.send_resp(550, &format!("Failed to open file: {}", e));
                    }
                }
            }
            "STOR" => {
                if args.is_empty() {
                    self.send_resp(501, "Syntax error in parameters: STOR <filename>");
                    return true;
                }
                let filepath = match resolve_safe_path(&self.root_dir, &self.current_rel_dir, args) {
                    Ok((_, p)) => p,
                    Err(()) => {
                        eprintln!("[SECURITY BREACH][TRAVERSAL] Session {} attempted unauthorized STOR traversal: '{}'", self.session_id, args);
                        self.send_resp(550, "Security violation: Traversal attempt logged and rejected.");
                        return true;
                    }
                };

                let mut data_stream = match self.accept_data_connection() {
                    Some(s) => s,
                    None => return true,
                };

                self.send_resp(150, &format!("Ok to send data for {}.", args));

                match File::create(&filepath) {
                    Ok(mut f) => {
                        let mut buf = [0u8; 8192];
                        loop {
                            match data_stream.read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => {
                                    if f.write_all(&buf[..n]).is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        drop(data_stream);
                        self.send_resp(226, "Transfer complete.");
                    }
                    Err(e) => {
                        drop(data_stream);
                        self.send_resp(550, &format!("Failed to create file: {}", e));
                    }
                }
            }
            "DELE" => {
                if args.is_empty() {
                    self.send_resp(501, "Syntax error in parameters: DELE <filename>");
                    return true;
                }
                let filepath = match resolve_safe_path(&self.root_dir, &self.current_rel_dir, args) {
                    Ok((_, p)) => p,
                    Err(()) => {
                        eprintln!("[SECURITY BREACH][TRAVERSAL] Session {} attempted unauthorized DELE traversal: '{}'", self.session_id, args);
                        self.send_resp(550, "Security violation: Traversal attempt logged and rejected.");
                        return true;
                    }
                };

                if fs::remove_file(filepath).is_ok() {
                    self.send_resp(250, "File deleted successfully.");
                } else {
                    self.send_resp(550, "Delete operation failed.");
                }
            }
            _ => {
                self.send_resp(502, "Command not implemented.");
            }
        }
        true
    }

    fn accept_data_connection(&mut self) -> Option<TcpStream> {
        let listener = match self.data_listener.take() {
            Some(l) => l,
            None => {
                self.send_resp(425, "Use PASV first.");
                return None;
            }
        };

        match listener.accept() {
            Ok((stream, _)) => Some(stream),
            Err(e) => {
                self.send_resp(425, &format!("Failed to accept data connection: {}", e));
                None
            }
        }
    }
}
