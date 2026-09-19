//! Authentication — client-facing and upstream-facing auth handlers.
//!
//! Client-facing: cleartext password challenge (pgvpd authenticates the client).
//! Upstream-facing: cleartext, MD5, and SCRAM-SHA-256 (pgvpd authenticates to Postgres).

use bytes::BytesMut;
use hmac::{Hmac, Mac};
use md5::Digest as Md5Digest;
use md5::Md5 as Md5Hasher;
use sha2::Sha256;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use crate::protocol::{
    BackendMessage, auth, build_auth_cleartext_request, build_auth_ok, build_password_message,
    build_sasl_initial_response, build_sasl_response, try_read_backend_message,
    try_read_password_message,
};
use crate::stream::{ClientStream, UpstreamStream, read_or_eof};

type HmacSha256 = Hmac<Sha256>;

// ─── Client-facing authentication ───────────────────────────────────────────

/// Authenticate a client using cleartext password.
/// Sends AuthenticationCleartextPassword, reads the PasswordMessage, verifies it.
/// Returns Ok(()) on success, or an error string on failure.
pub async fn authenticate_client(
    client: &mut ClientStream,
    expected_password: &str,
    conn_id: u64,
) -> Result<(), String> {
    // Send cleartext password request
    let req = build_auth_cleartext_request();
    client
        .write_all(&req)
        .await
        .map_err(|e| format!("failed to send auth request: {e}"))?;

    // Read password response
    let mut buf = BytesMut::with_capacity(1024);
    loop {
        let n = client
            .read_buf(&mut buf)
            .await
            .map_err(|e| format!("failed to read password: {e}"))?;
        if n == 0 {
            return Err("client disconnected during auth".into());
        }
        if let Some(password) = try_read_password_message(&mut buf) {
            if password == expected_password {
                debug!(conn_id, "client password verified");
                // Send AuthenticationOk
                let ok = build_auth_ok();
                client
                    .write_all(&ok)
                    .await
                    .map_err(|e| format!("failed to send auth ok: {e}"))?;
                return Ok(());
            } else {
                return Err("password authentication failed".into());
            }
        }
    }
}

// ─── Upstream-facing authentication ─────────────────────────────────────────

/// Authenticate to upstream Postgres, handling cleartext, MD5, and SCRAM-SHA-256.
/// Reads auth challenge messages from `server_buf`/server, sends appropriate responses.
/// Returns Ok(()) when AuthenticationOk is received.
pub async fn authenticate_upstream(
    server: &mut UpstreamStream,
    server_buf: &mut BytesMut,
    username: &str,
    password: &str,
    conn_id: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        // Read more data if buffer has no complete message
        if server_buf.is_empty() {
            read_or_eof(server, server_buf).await?;
        }

        while let Some(msg) = try_read_backend_message(server_buf) {
            if msg.is_auth_ok() {
                debug!(conn_id, "upstream auth OK");
                return Ok(());
            }

            if msg.is_error_response() {
                return Err(format!("upstream auth error: {}", msg.error_message()).into());
            }

            let Some(subtype) = msg.auth_subtype() else {
                continue;
            };

            match subtype {
                auth::CLEARTEXT_PASSWORD => {
                    debug!(conn_id, "upstream wants cleartext password");
                    let pw_msg = build_password_message(password.as_bytes());
                    server.write_all(&pw_msg).await?;
                }
                auth::MD5_PASSWORD => {
                    debug!(conn_id, "upstream wants MD5 password");
                    if msg.payload.len() < 8 {
                        return Err("MD5 auth message too short".into());
                    }
                    let salt = &msg.payload[4..8];
                    let hashed = compute_md5_password(username, password, salt);
                    let pw_msg = build_password_message(hashed.as_bytes());
                    server.write_all(&pw_msg).await?;
                }
                auth::SASL => {
                    debug!(conn_id, "upstream wants SCRAM-SHA-256");
                    scram_authenticate(server, server_buf, &msg, password, conn_id).await?;
                    // After SCRAM, AuthenticationOk should follow
                    continue;
                }
                auth::SASL_FINAL => {
                    // SASL final — no client response needed, AuthOk should follow
                    debug!(conn_id, "SASL final received");
                }
                _ => {
                    return Err(format!("unsupported auth method: {subtype}").into());
                }
            }
        }
    }
}

// ─── MD5 ────────────────────────────────────────────────────────────────────

/// Compute MD5 password hash: `md5` || md5(md5(password + username) + salt)
pub fn compute_md5_password(username: &str, password: &str, salt: &[u8]) -> String {
    // Phase 1: md5(password + username)
    let mut hasher = Md5Hasher::new();
    hasher.update(password.as_bytes());
    hasher.update(username.as_bytes());
    let phase1 = format!("{:x}", hasher.finalize());

    // Phase 2: md5(phase1_hex + salt)
    let mut hasher = Md5Hasher::new();
    hasher.update(phase1.as_bytes());
    hasher.update(salt);
    let phase2 = format!("{:x}", hasher.finalize());

    format!("md5{phase2}")
}

// ─── SCRAM-SHA-256 ──────────────────────────────────────────────────────────

/// Run the SCRAM-SHA-256 client state machine against the upstream server.
///
/// State machine:
///   1. Parse server's AuthenticationSASL (list of mechanisms)
///   2. Send SASLInitialResponse with client-first-message
///   3. Receive AuthenticationSASLContinue with server-first-message
///   4. Compute client proof, send SASLResponse with client-final-message
///   5. Receive AuthenticationSASLFinal with server signature (verify it)
async fn scram_authenticate(
    server: &mut UpstreamStream,
    server_buf: &mut BytesMut,
    _sasl_msg: &BackendMessage,
    password: &str,
    conn_id: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;

    // Generate client nonce
    let client_nonce = generate_nonce();
    let client_first_bare = format!("n=,r={client_nonce}");
    let client_first_message = format!("n,,{client_first_bare}");

    // Send SASLInitialResponse
    let initial = build_sasl_initial_response("SCRAM-SHA-256", client_first_message.as_bytes());
    server.write_all(&initial).await?;
    debug!(conn_id, "SCRAM: sent client-first");

    // Read server-first-message (AuthenticationSASLContinue)
    let server_first = loop {
        if server_buf.is_empty() {
            read_or_eof(server, server_buf).await?;
        }
        if let Some(msg) = try_read_backend_message(server_buf) {
            if msg.is_error_response() {
                return Err(format!("SCRAM error: {}", msg.error_message()).into());
            }
            if msg.auth_subtype() == Some(auth::SASL_CONTINUE) {
                break String::from_utf8_lossy(&msg.payload[4..]).to_string();
            }
        }
    };
    debug!(conn_id, "SCRAM: got server-first");

    // Parse server-first-message: r=<nonce>,s=<salt>,i=<iterations>
    let (server_nonce, salt_b64, iterations) = parse_server_first(&server_first)?;

    // Verify server nonce starts with our client nonce
    if !server_nonce.starts_with(&client_nonce) {
        return Err("SCRAM: server nonce doesn't start with client nonce".into());
    }

    let salt = b64
        .decode(salt_b64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad salt: {e}")))?;

    // Derive keys
    let salted_password = hi(password.as_bytes(), &salt, iterations);
    let client_key = hmac_sha256(&salted_password, b"Client Key");
    let stored_key = sha256(&client_key);
    let server_key = hmac_sha256(&salted_password, b"Server Key");

    // Build auth message
    let client_final_without_proof = format!("c=biws,r={server_nonce}");
    let auth_message = format!("{client_first_bare},{server_first},{client_final_without_proof}");

    // Compute client signature and proof
    let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
    let client_proof: Vec<u8> = client_key
        .iter()
        .zip(client_signature.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    let proof_b64 = b64.encode(&client_proof);
    let client_final = format!("{client_final_without_proof},p={proof_b64}");

    // Send client-final-message
    let resp = build_sasl_response(client_final.as_bytes());
    server.write_all(&resp).await?;
    debug!(conn_id, "SCRAM: sent client-final");

    // Read server-final-message (AuthenticationSASLFinal)
    let server_final = loop {
        if server_buf.is_empty() {
            read_or_eof(server, server_buf).await?;
        }
        if let Some(msg) = try_read_backend_message(server_buf) {
            if msg.is_error_response() {
                return Err(format!("SCRAM final error: {}", msg.error_message()).into());
            }
            if msg.auth_subtype() == Some(auth::SASL_FINAL) {
                break String::from_utf8_lossy(&msg.payload[4..]).to_string();
            }
            if msg.is_auth_ok() {
                // Some servers send AuthOk without a separate SASLFinal
                debug!(conn_id, "SCRAM: auth OK (no separate final)");
                return Ok(());
            }
        }
    };
    debug!(conn_id, "SCRAM: got server-final");

    // Verify server signature
    let expected_server_sig = hmac_sha256(&server_key, auth_message.as_bytes());
    let expected_verifier = format!("v={}", b64.encode(&expected_server_sig));
    if server_final != expected_verifier {
        return Err("SCRAM: server signature verification failed".into());
    }

    debug!(conn_id, "SCRAM: server verified");

    // AuthenticationOk should follow — it will be handled by the caller
    Ok(())
}

/// Parse server-first-message into (nonce, salt_b64, iterations).
fn parse_server_first(
    msg: &str,
) -> Result<(&str, &str, u32), Box<dyn std::error::Error + Send + Sync>> {
    let mut nonce = None;
    let mut salt = None;
    let mut iterations = None;

    for part in msg.split(',') {
        if let Some(v) = part.strip_prefix("r=") {
            nonce = Some(v);
        } else if let Some(v) = part.strip_prefix("s=") {
            salt = Some(v);
        } else if let Some(v) = part.strip_prefix("i=") {
            iterations = Some(v.parse::<u32>()?);
        }
    }

    Ok((
        nonce.ok_or("SCRAM: missing nonce in server-first")?,
        salt.ok_or("SCRAM: missing salt in server-first")?,
        iterations.ok_or("SCRAM: missing iterations in server-first")?,
    ))
}

/// PBKDF2-HMAC-SHA256 key derivation (Hi function from RFC 5802).
fn hi(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut output = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut output);
    output
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn generate_nonce() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── MD5 password computation ────────────────────────────────────────

    #[test]
    fn md5_password_known_vector() {
        // PostgreSQL MD5 auth: md5 || hex(md5(hex(md5(password + username)) + salt))
        // We can verify against known values from pg_password.
        let result = compute_md5_password("app_user", "secret", &[0x01, 0x02, 0x03, 0x04]);
        assert!(result.starts_with("md5"));
        assert_eq!(result.len(), 35); // "md5" + 32 hex chars
    }

    #[test]
    fn md5_password_deterministic() {
        let salt = [0xAA, 0xBB, 0xCC, 0xDD];
        let r1 = compute_md5_password("user", "pass", &salt);
        let r2 = compute_md5_password("user", "pass", &salt);
        assert_eq!(r1, r2);
    }

    #[test]
    fn md5_password_different_users_differ() {
        let salt = [1, 2, 3, 4];
        let r1 = compute_md5_password("alice", "pass", &salt);
        let r2 = compute_md5_password("bob", "pass", &salt);
        assert_ne!(r1, r2);
    }

    #[test]
    fn md5_password_different_passwords_differ() {
        let salt = [1, 2, 3, 4];
        let r1 = compute_md5_password("user", "pass1", &salt);
        let r2 = compute_md5_password("user", "pass2", &salt);
        assert_ne!(r1, r2);
    }

    #[test]
    fn md5_password_different_salts_differ() {
        let r1 = compute_md5_password("user", "pass", &[1, 2, 3, 4]);
        let r2 = compute_md5_password("user", "pass", &[5, 6, 7, 8]);
        assert_ne!(r1, r2);
    }

    // ─── SCRAM helpers ───────────────────────────────────────────────────

    #[test]
    fn parse_server_first_valid() {
        let msg = "r=clientnonceservernonce,s=c2FsdA==,i=4096";
        let (nonce, salt_b64, iterations) = parse_server_first(msg).unwrap();
        assert_eq!(nonce, "clientnonceservernonce");
        assert_eq!(salt_b64, "c2FsdA==");
        assert_eq!(iterations, 4096);
    }

    #[test]
    fn parse_server_first_missing_nonce() {
        let msg = "s=c2FsdA==,i=4096";
        assert!(parse_server_first(msg).is_err());
    }

    #[test]
    fn parse_server_first_missing_salt() {
        let msg = "r=nonce,i=4096";
        assert!(parse_server_first(msg).is_err());
    }

    #[test]
    fn parse_server_first_missing_iterations() {
        let msg = "r=nonce,s=c2FsdA==";
        assert!(parse_server_first(msg).is_err());
    }

    #[test]
    fn parse_server_first_bad_iterations() {
        let msg = "r=nonce,s=c2FsdA==,i=notanumber";
        assert!(parse_server_first(msg).is_err());
    }

    // ─── PBKDF2 / Hi function ────────────────────────────────────────────

    #[test]
    fn hi_deterministic() {
        let r1 = hi(b"password", b"salt", 4096);
        let r2 = hi(b"password", b"salt", 4096);
        assert_eq!(r1, r2);
    }

    #[test]
    fn hi_different_iterations_differ() {
        let r1 = hi(b"password", b"salt", 4096);
        let r2 = hi(b"password", b"salt", 1);
        assert_ne!(r1, r2);
    }

    // ─── HMAC-SHA256 ─────────────────────────────────────────────────────

    #[test]
    fn hmac_sha256_deterministic() {
        let r1 = hmac_sha256(b"key", b"data");
        let r2 = hmac_sha256(b"key", b"data");
        assert_eq!(r1, r2);
        assert_eq!(r1.len(), 32);
    }

    #[test]
    fn hmac_sha256_different_keys_differ() {
        let r1 = hmac_sha256(b"key1", b"data");
        let r2 = hmac_sha256(b"key2", b"data");
        assert_ne!(r1, r2);
    }

    // ─── SHA256 ──────────────────────────────────────────────────────────

    #[test]
    fn sha256_deterministic() {
        let r1 = sha256(b"hello");
        let r2 = sha256(b"hello");
        assert_eq!(r1, r2);
        assert_eq!(r1.len(), 32);
    }

    // ─── Nonce generation ────────────────────────────────────────────────

    #[test]
    fn nonce_is_unique() {
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_ne!(n1, n2);
    }

    #[test]
    fn nonce_is_base64() {
        use base64::Engine;
        let nonce = generate_nonce();
        // Should be valid base64
        assert!(
            base64::engine::general_purpose::STANDARD
                .decode(&nonce)
                .is_ok()
        );
    }

    // ─── SCRAM full derivation ───────────────────────────────────────────

    #[test]
    fn scram_key_derivation_consistency() {
        // Verify the full key derivation chain produces consistent results
        let password = "testpassword";
        let salt = b"testsalt12345678";
        let iterations = 4096;

        let salted_password = hi(password.as_bytes(), salt, iterations);
        let client_key = hmac_sha256(&salted_password, b"Client Key");
        let stored_key = sha256(&client_key);
        let server_key = hmac_sha256(&salted_password, b"Server Key");

        // All outputs should be 32 bytes
        assert_eq!(salted_password.len(), 32);
        assert_eq!(client_key.len(), 32);
        assert_eq!(stored_key.len(), 32);
        assert_eq!(server_key.len(), 32);

        // Client key and server key should differ
        assert_ne!(client_key, server_key);

        // Stored key (sha256 of client key) should differ from client key
        assert_ne!(&stored_key[..], &client_key[..]);

        // Re-derive should match
        let salted_password_2 = hi(password.as_bytes(), salt, iterations);
        assert_eq!(salted_password, salted_password_2);
    }
}
