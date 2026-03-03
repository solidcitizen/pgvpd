//! Postgres Wire Protocol Primitives
//!
//! Minimum subset of the Postgres v3 wire protocol needed for the proxy:
//! parse StartupMessages, detect auth completion, inject SET commands,
//! frame messages for transparent forwarding.
//!
//! Reference: https://www.postgresql.org/docs/current/protocol-message-formats.html

use bytes::{Buf, BufMut, BytesMut};
use std::collections::HashMap;
use std::io;

// ─── Constants ──────────────────────────────────────────────────────────────

/// Postgres protocol version 3.0
const PROTOCOL_VERSION_30: i32 = 196608; // 0x00030000

/// SSLRequest magic number
const SSL_REQUEST_CODE: i32 = 80877103;

/// CancelRequest magic number
const CANCEL_REQUEST_CODE: i32 = 80877102;

/// Single byte denying SSL
pub const SSL_DENY: &[u8] = b"N";

/// Backend message types we care about
pub mod backend {
    pub const AUTHENTICATION: u8 = b'R';
    pub const PARAMETER_STATUS: u8 = b'S';
    pub const BACKEND_KEY_DATA: u8 = b'K';
    pub const READY_FOR_QUERY: u8 = b'Z';
    pub const COMMAND_COMPLETE: u8 = b'C';
    pub const ERROR_RESPONSE: u8 = b'E';
    pub const ROW_DESCRIPTION: u8 = b'T';
    pub const DATA_ROW: u8 = b'D';
    pub const EMPTY_QUERY_RESPONSE: u8 = b'I';
}

/// Authentication subtypes
pub mod auth {
    pub const OK: i32 = 0;
    pub const CLEARTEXT_PASSWORD: i32 = 3;
    pub const MD5_PASSWORD: i32 = 5;
    pub const SASL: i32 = 10;
    pub const SASL_CONTINUE: i32 = 11;
    pub const SASL_FINAL: i32 = 12;
}

// ─── Startup Message Types ──────────────────────────────────────────────────

/// What the client sent as its first message.
pub enum StartupType {
    /// SSLRequest — client wants to negotiate TLS.
    SslRequest,
    /// CancelRequest — client wants to cancel a query.
    CancelRequest,
    /// Normal StartupMessage with parameters.
    Startup(StartupMessage),
}

/// Parsed StartupMessage parameters.
pub struct StartupMessage {
    pub params: HashMap<String, String>,
}

// ─── Backend Message ────────────────────────────────────────────────────────

/// A complete message from the Postgres backend.
pub struct BackendMessage {
    /// Message type byte (e.g., b'R' for Authentication)
    pub msg_type: u8,
    /// Complete raw bytes including type and length (for forwarding)
    pub raw: BytesMut,
    /// Payload after the length field
    pub payload: BytesMut,
}

impl BackendMessage {
    /// Is this AuthenticationOk?
    pub fn is_auth_ok(&self) -> bool {
        self.msg_type == backend::AUTHENTICATION
            && self.payload.len() >= 4
            && (&self.payload[..4]).get_i32() == auth::OK
    }

    /// Is this an auth challenge that expects a client response?
    /// (Not AuthOk or SASLFinal, which require no client reply.)
    pub fn is_auth_challenge(&self) -> bool {
        if self.msg_type != backend::AUTHENTICATION || self.payload.len() < 4 {
            return false;
        }
        let subtype = i32::from_be_bytes([
            self.payload[0],
            self.payload[1],
            self.payload[2],
            self.payload[3],
        ]);
        subtype != auth::OK && subtype != auth::SASL_FINAL
    }

    /// Is this ReadyForQuery?
    pub fn is_ready_for_query(&self) -> bool {
        self.msg_type == backend::READY_FOR_QUERY
    }

    /// Is this ErrorResponse?
    pub fn is_error_response(&self) -> bool {
        self.msg_type == backend::ERROR_RESPONSE
    }

    /// Is this ParameterStatus?
    pub fn is_parameter_status(&self) -> bool {
        self.msg_type == backend::PARAMETER_STATUS
    }

    /// Is this BackendKeyData?
    pub fn is_backend_key_data(&self) -> bool {
        self.msg_type == backend::BACKEND_KEY_DATA
    }

    /// Is this RowDescription?
    #[allow(dead_code)]
    pub fn is_row_description(&self) -> bool {
        self.msg_type == backend::ROW_DESCRIPTION
    }

    /// Is this DataRow?
    #[allow(dead_code)]
    pub fn is_data_row(&self) -> bool {
        self.msg_type == backend::DATA_ROW
    }

    /// Return the auth subtype (e.g. OK=0, CLEARTEXT=3, MD5=5, SASL=10).
    /// Returns `None` if this isn't an Authentication message or payload is too short.
    pub fn auth_subtype(&self) -> Option<i32> {
        if self.msg_type != backend::AUTHENTICATION || self.payload.len() < 4 {
            return None;
        }
        Some(i32::from_be_bytes([
            self.payload[0],
            self.payload[1],
            self.payload[2],
            self.payload[3],
        ]))
    }

    /// Extract human-readable error message from an ErrorResponse.
    pub fn error_message(&self) -> String {
        if !self.is_error_response() {
            return String::from("not an error");
        }
        let mut parts = Vec::new();
        let mut offset = 0;
        let data = &self.payload;

        while offset < data.len() {
            let field_type = data[offset];
            if field_type == 0 {
                break;
            }
            offset += 1;

            // Find null terminator
            let str_end = data[offset..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| offset + p)
                .unwrap_or(data.len());

            let value = String::from_utf8_lossy(&data[offset..str_end]).to_string();
            offset = str_end + 1;

            match field_type {
                b'M' => parts.insert(0, value), // Message
                b'D' => parts.push(value),      // Detail
                _ => {}
            }
        }

        if parts.is_empty() {
            String::from("unknown error")
        } else {
            parts.join(": ")
        }
    }
}

// ─── Parsing ────────────────────────────────────────────────────────────────

/// Try to read a complete startup-phase message from the buffer.
///
/// Startup messages have no type byte — they start with Int32 length.
/// Returns `None` if not enough data. Consumes the message from `buf` on success.
pub fn try_read_startup(buf: &mut BytesMut) -> Option<StartupType> {
    if buf.len() < 8 {
        return None;
    }

    let length = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if !(8..=10240).contains(&length) {
        return None; // sanity check
    }
    if buf.len() < length {
        return None; // need more data
    }

    let msg_buf = buf.split_to(length);
    let version = i32::from_be_bytes([msg_buf[4], msg_buf[5], msg_buf[6], msg_buf[7]]);

    match version {
        v if v == SSL_REQUEST_CODE => Some(StartupType::SslRequest),
        v if v == CANCEL_REQUEST_CODE => Some(StartupType::CancelRequest),
        _ => {
            // Parse key-value pairs
            let mut params = HashMap::new();
            let mut offset = 8;

            while offset < length - 1 {
                // Read key
                let key_end = msg_buf[offset..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| offset + p);
                let Some(key_end) = key_end else { break };
                let key = String::from_utf8_lossy(&msg_buf[offset..key_end]).to_string();
                offset = key_end + 1;

                // Read value
                let val_end = msg_buf[offset..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| offset + p);
                let Some(val_end) = val_end else { break };
                let value = String::from_utf8_lossy(&msg_buf[offset..val_end]).to_string();
                offset = val_end + 1;

                if !key.is_empty() {
                    params.insert(key, value);
                }
            }

            Some(StartupType::Startup(StartupMessage { params }))
        }
    }
}

/// Try to read a complete backend message from the buffer.
///
/// Backend messages: `u8 type | i32 length | payload`
/// Length includes itself (4 bytes) but not the type byte.
/// Returns `None` if not enough data. Consumes the message from `buf` on success.
pub fn try_read_backend_message(buf: &mut BytesMut) -> Option<BackendMessage> {
    if buf.len() < 5 {
        return None;
    }

    let msg_type = buf[0];
    let length = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    let total_length = 1 + length; // type byte + length value

    if buf.len() < total_length {
        return None;
    }

    let raw = BytesMut::from(&buf[..total_length]);
    let payload = BytesMut::from(&buf[5..total_length]);
    buf.advance(total_length);

    Some(BackendMessage {
        msg_type,
        raw,
        payload,
    })
}

// ─── Building ───────────────────────────────────────────────────────────────

/// Build a StartupMessage with the given parameters.
pub fn build_startup_message(params: &HashMap<String, String>) -> BytesMut {
    // Calculate size: 4 (length) + 4 (version) + key-value pairs + terminal null
    let mut data_len = 4; // version
    for (key, value) in params {
        data_len += key.len() + 1 + value.len() + 1;
    }
    data_len += 1; // terminal null

    let total_len = 4 + data_len; // 4 for length field
    let mut buf = BytesMut::with_capacity(total_len);

    buf.put_i32(total_len as i32);
    buf.put_i32(PROTOCOL_VERSION_30);

    for (key, value) in params {
        buf.put_slice(key.as_bytes());
        buf.put_u8(0);
        buf.put_slice(value.as_bytes());
        buf.put_u8(0);
    }
    buf.put_u8(0); // terminal null

    buf
}

/// Build a SimpleQuery ('Q') message.
pub fn build_query_message(sql: &str) -> BytesMut {
    let msg_len = 4 + sql.len() + 1; // length field + sql + null
    let mut buf = BytesMut::with_capacity(1 + msg_len);

    buf.put_u8(b'Q');
    buf.put_i32(msg_len as i32);
    buf.put_slice(sql.as_bytes());
    buf.put_u8(0);

    buf
}

/// Build an ErrorResponse ('E') message.
pub fn build_error_response(severity: &str, sqlstate: &str, message: &str) -> BytesMut {
    let fields: Vec<(u8, &str)> = vec![
        (b'S', severity),
        (b'V', severity),
        (b'C', sqlstate),
        (b'M', message),
    ];

    // Calculate fields length
    let fields_len: usize = fields.iter().map(|(_, v)| 1 + v.len() + 1).sum::<usize>() + 1; // +1 terminal null
    let msg_len = 4 + fields_len;

    let mut buf = BytesMut::with_capacity(1 + msg_len);
    buf.put_u8(b'E');
    buf.put_i32(msg_len as i32);

    for (field_type, value) in &fields {
        buf.put_u8(*field_type);
        buf.put_slice(value.as_bytes());
        buf.put_u8(0);
    }
    buf.put_u8(0); // terminal null

    buf
}

/// Build an AuthenticationCleartextPassword request (server → client).
pub fn build_auth_cleartext_request() -> BytesMut {
    // 'R' | int32 len(8) | int32 subtype(3)
    let mut buf = BytesMut::with_capacity(9);
    buf.put_u8(backend::AUTHENTICATION);
    buf.put_i32(8); // length: 4 (len field) + 4 (subtype)
    buf.put_i32(auth::CLEARTEXT_PASSWORD);
    buf
}

/// Build an AuthenticationOk message (server → client).
pub fn build_auth_ok() -> BytesMut {
    let mut buf = BytesMut::with_capacity(9);
    buf.put_u8(backend::AUTHENTICATION);
    buf.put_i32(8);
    buf.put_i32(auth::OK);
    buf
}

/// Try to read a PasswordMessage ('p') from the client buffer.
/// Returns the password string (without null terminator) or None if not enough data.
pub fn try_read_password_message(buf: &mut BytesMut) -> Option<String> {
    if buf.len() < 5 {
        return None;
    }
    if buf[0] != b'p' {
        return None;
    }
    let length = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    let total = 1 + length;
    if buf.len() < total {
        return None;
    }
    // Password is between offset 5 and total-1 (strip null terminator)
    let password_end = if total > 5 && buf[total - 1] == 0 {
        total - 1
    } else {
        total
    };
    let password = String::from_utf8_lossy(&buf[5..password_end]).to_string();
    buf.advance(total);
    Some(password)
}

/// Build a PasswordMessage ('p') for sending to the server.
pub fn build_password_message(password: &[u8]) -> BytesMut {
    let msg_len = 4 + password.len() + 1; // length field + password + null
    let mut buf = BytesMut::with_capacity(1 + msg_len);
    buf.put_u8(b'p');
    buf.put_i32(msg_len as i32);
    buf.put_slice(password);
    buf.put_u8(0);
    buf
}

/// Build a SASLInitialResponse message ('p') with mechanism name and initial data.
pub fn build_sasl_initial_response(mechanism: &str, data: &[u8]) -> BytesMut {
    // 'p' | int32 len | mechanism\0 | int32 data_len | data
    let msg_len = 4 + mechanism.len() + 1 + 4 + data.len();
    let mut buf = BytesMut::with_capacity(1 + msg_len);
    buf.put_u8(b'p');
    buf.put_i32(msg_len as i32);
    buf.put_slice(mechanism.as_bytes());
    buf.put_u8(0);
    buf.put_i32(data.len() as i32);
    buf.put_slice(data);
    buf
}

/// Build a SASLResponse message ('p') with response data.
pub fn build_sasl_response(data: &[u8]) -> BytesMut {
    let msg_len = 4 + data.len();
    let mut buf = BytesMut::with_capacity(1 + msg_len);
    buf.put_u8(b'p');
    buf.put_i32(msg_len as i32);
    buf.put_slice(data);
    buf
}

// ─── SQL Escaping ───────────────────────────────────────────────────────────

/// Escape a value as a SQL single-quoted literal.
/// Rejects characters that have no business in a tenant ID.
#[allow(dead_code)]
pub fn escape_literal(value: &str) -> io::Result<String> {
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid tenant ID: disallowed characters in '{value}'"),
        ));
    }
    Ok(format!("'{}'", value.replace('\'', "''")))
}

/// Escape a value as a SQL single-quoted literal for SET commands.
///
/// Unlike `escape_literal()` which restricts characters (for untrusted tenant IDs),
/// this allows any content (resolver results come from the database and may contain
/// array literals like `{a,b,c}`, commas, spaces, etc.). Defense is quote-doubling only.
pub fn escape_set_value(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Quote an identifier (double-quoted).
pub fn quote_ident(value: &str) -> io::Result<String> {
    if !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid identifier: '{value}'"),
        ));
    }
    Ok(format!("\"{}\"", value.replace('"', "\"\"")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    // ─── Startup message parsing ─────────────────────────────────────────

    fn build_raw_startup(version: i32, params: &[(&str, &str)]) -> BytesMut {
        let mut data = BytesMut::new();
        data.put_i32(0); // placeholder for length
        data.put_i32(version);
        for (k, v) in params {
            data.put_slice(k.as_bytes());
            data.put_u8(0);
            data.put_slice(v.as_bytes());
            data.put_u8(0);
        }
        data.put_u8(0); // terminal null
        let len = data.len() as i32;
        data[0..4].copy_from_slice(&len.to_be_bytes());
        data
    }

    #[test]
    fn parse_normal_startup() {
        let mut buf = build_raw_startup(
            PROTOCOL_VERSION_30,
            &[("user", "admin"), ("database", "mydb")],
        );
        match try_read_startup(&mut buf) {
            Some(StartupType::Startup(msg)) => {
                assert_eq!(msg.params.get("user").unwrap(), "admin");
                assert_eq!(msg.params.get("database").unwrap(), "mydb");
            }
            other => panic!("expected Startup, got {:?}", other.is_some()),
        }
        assert!(buf.is_empty());
    }

    #[test]
    fn parse_ssl_request() {
        let mut buf = BytesMut::new();
        buf.put_i32(8);
        buf.put_i32(SSL_REQUEST_CODE);
        assert!(matches!(
            try_read_startup(&mut buf),
            Some(StartupType::SslRequest)
        ));
    }

    #[test]
    fn parse_cancel_request() {
        let mut buf = BytesMut::new();
        buf.put_i32(16); // length: 8 for header + 8 for pid+key
        buf.put_i32(CANCEL_REQUEST_CODE);
        buf.put_i32(1234); // pid
        buf.put_i32(5678); // secret key
        assert!(matches!(
            try_read_startup(&mut buf),
            Some(StartupType::CancelRequest)
        ));
    }

    #[test]
    fn truncated_startup_returns_none() {
        // Only 4 bytes — need at least 8
        let mut buf = BytesMut::from(&[0u8, 0, 0, 8][..]);
        assert!(try_read_startup(&mut buf).is_none());
    }

    #[test]
    fn incomplete_startup_returns_none() {
        // Header says 20 bytes but buffer only has 10
        let mut buf = BytesMut::new();
        buf.put_i32(20);
        buf.put_i32(PROTOCOL_VERSION_30);
        buf.put_u8(0);
        buf.put_u8(0);
        assert!(try_read_startup(&mut buf).is_none());
    }

    #[test]
    fn oversized_startup_returns_none() {
        // Length > 10240 sanity check
        let mut buf = BytesMut::new();
        buf.put_i32(20000);
        buf.put_i32(PROTOCOL_VERSION_30);
        buf.extend_from_slice(&vec![0u8; 20000]);
        assert!(try_read_startup(&mut buf).is_none());
    }

    #[test]
    fn startup_with_empty_params() {
        // Just version + terminal null, no key-value pairs
        let mut buf = build_raw_startup(PROTOCOL_VERSION_30, &[]);
        match try_read_startup(&mut buf) {
            Some(StartupType::Startup(msg)) => {
                assert!(msg.params.is_empty());
            }
            _ => panic!("expected empty Startup"),
        }
    }

    // ─── Backend message framing ─────────────────────────────────────────

    fn build_raw_backend_message(msg_type: u8, payload: &[u8]) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u8(msg_type);
        buf.put_i32((4 + payload.len()) as i32); // length includes itself
        buf.put_slice(payload);
        buf
    }

    #[test]
    fn parse_backend_message_ready_for_query() {
        let mut buf = build_raw_backend_message(backend::READY_FOR_QUERY, &[b'I']);
        let msg = try_read_backend_message(&mut buf).unwrap();
        assert!(msg.is_ready_for_query());
        assert_eq!(msg.payload.len(), 1);
        assert!(buf.is_empty());
    }

    #[test]
    fn parse_backend_message_auth_ok() {
        let mut payload = BytesMut::new();
        payload.put_i32(auth::OK);
        let mut buf = build_raw_backend_message(backend::AUTHENTICATION, &payload);
        let msg = try_read_backend_message(&mut buf).unwrap();
        assert!(msg.is_auth_ok());
    }

    #[test]
    fn truncated_backend_message_returns_none() {
        // Only 3 bytes — need at least 5 (1 type + 4 length)
        let mut buf = BytesMut::from(&[b'Z', 0, 0][..]);
        assert!(try_read_backend_message(&mut buf).is_none());
    }

    #[test]
    fn incomplete_backend_message_returns_none() {
        // Header says 10 bytes of payload but only 2 present
        let mut buf = BytesMut::new();
        buf.put_u8(b'Z');
        buf.put_i32(10); // length field = 10, so total = 11
        buf.put_u8(b'I');
        buf.put_u8(0);
        assert!(try_read_backend_message(&mut buf).is_none());
    }

    #[test]
    fn auth_challenge_detection() {
        // SASL (10) should be a challenge
        let mut payload = BytesMut::new();
        payload.put_i32(auth::SASL);
        let mut buf = build_raw_backend_message(backend::AUTHENTICATION, &payload);
        let msg = try_read_backend_message(&mut buf).unwrap();
        assert!(msg.is_auth_challenge());

        // MD5 (5) should be a challenge
        let mut payload = BytesMut::new();
        payload.put_i32(auth::MD5_PASSWORD);
        payload.put_slice(&[1, 2, 3, 4]); // salt
        let mut buf = build_raw_backend_message(backend::AUTHENTICATION, &payload);
        let msg = try_read_backend_message(&mut buf).unwrap();
        assert!(msg.is_auth_challenge());

        // AuthOk (0) should NOT be a challenge
        let mut payload = BytesMut::new();
        payload.put_i32(auth::OK);
        let mut buf = build_raw_backend_message(backend::AUTHENTICATION, &payload);
        let msg = try_read_backend_message(&mut buf).unwrap();
        assert!(!msg.is_auth_challenge());

        // SASL_FINAL (12) should NOT be a challenge
        let mut payload = BytesMut::new();
        payload.put_i32(auth::SASL_FINAL);
        let mut buf = build_raw_backend_message(backend::AUTHENTICATION, &payload);
        let msg = try_read_backend_message(&mut buf).unwrap();
        assert!(!msg.is_auth_challenge());
    }

    #[test]
    fn auth_subtype_extraction() {
        // Non-auth message returns None
        let mut buf = build_raw_backend_message(backend::READY_FOR_QUERY, &[b'I']);
        let msg = try_read_backend_message(&mut buf).unwrap();
        assert_eq!(msg.auth_subtype(), None);

        // Auth message with short payload returns None
        let mut buf = build_raw_backend_message(backend::AUTHENTICATION, &[0, 0]);
        let msg = try_read_backend_message(&mut buf).unwrap();
        assert_eq!(msg.auth_subtype(), None);
    }

    #[test]
    fn error_response_parsing() {
        // Build an ErrorResponse with M and D fields
        let mut payload = BytesMut::new();
        payload.put_u8(b'S'); // Severity
        payload.put_slice(b"ERROR\0");
        payload.put_u8(b'M'); // Message
        payload.put_slice(b"relation does not exist\0");
        payload.put_u8(b'D'); // Detail
        payload.put_slice(b"table \"foo\" not found\0");
        payload.put_u8(0); // terminator

        let mut buf = build_raw_backend_message(backend::ERROR_RESPONSE, &payload);
        let msg = try_read_backend_message(&mut buf).unwrap();
        assert!(msg.is_error_response());
        let err = msg.error_message();
        assert!(err.contains("relation does not exist"));
        assert!(err.contains("table \"foo\" not found"));
    }

    #[test]
    fn error_response_empty_payload() {
        let mut payload = BytesMut::new();
        payload.put_u8(0); // just terminator
        let mut buf = build_raw_backend_message(backend::ERROR_RESPONSE, &payload);
        let msg = try_read_backend_message(&mut buf).unwrap();
        assert_eq!(msg.error_message(), "unknown error");
    }

    #[test]
    fn non_error_message_returns_not_an_error() {
        let mut buf = build_raw_backend_message(backend::READY_FOR_QUERY, &[b'I']);
        let msg = try_read_backend_message(&mut buf).unwrap();
        assert_eq!(msg.error_message(), "not an error");
    }

    // ─── Message building ────────────────────────────────────────────────

    #[test]
    fn build_and_parse_startup_roundtrip() {
        let mut params = HashMap::new();
        params.insert("user".to_string(), "app_user".to_string());
        params.insert("database".to_string(), "mydb".to_string());
        let mut buf = build_startup_message(&params);
        match try_read_startup(&mut buf) {
            Some(StartupType::Startup(msg)) => {
                assert_eq!(msg.params.get("user").unwrap(), "app_user");
                assert_eq!(msg.params.get("database").unwrap(), "mydb");
            }
            _ => panic!("roundtrip failed"),
        }
    }

    #[test]
    fn build_query_message_format() {
        let buf = build_query_message("SELECT 1");
        assert_eq!(buf[0], b'Q');
        let len = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        assert_eq!(len, 4 + 8 + 1); // length field + "SELECT 1" + null
        assert_eq!(buf[buf.len() - 1], 0); // null terminator
    }

    #[test]
    fn build_and_parse_password_roundtrip() {
        let mut buf = build_password_message(b"secret123");
        let pw = try_read_password_message(&mut buf).unwrap();
        assert_eq!(pw, "secret123");
    }

    #[test]
    fn password_message_wrong_type_returns_none() {
        // Build a message with type 'Q' instead of 'p'
        let mut buf = BytesMut::new();
        buf.put_u8(b'Q');
        buf.put_i32(12);
        buf.put_slice(b"secret\0");
        buf.put_u8(0);
        assert!(try_read_password_message(&mut buf).is_none());
    }

    #[test]
    fn password_message_incomplete_returns_none() {
        let mut buf = BytesMut::new();
        buf.put_u8(b'p');
        buf.put_i32(100); // claims 100 bytes but we only have a few
        buf.put_slice(b"short");
        assert!(try_read_password_message(&mut buf).is_none());
    }

    // ─── SQL escaping ────────────────────────────────────────────────────

    #[test]
    fn escape_literal_valid_values() {
        assert_eq!(escape_literal("tenant_a").unwrap(), "'tenant_a'");
        assert_eq!(escape_literal("my-tenant").unwrap(), "'my-tenant'");
        assert_eq!(escape_literal("tenant.sub").unwrap(), "'tenant.sub'");
        assert_eq!(escape_literal("abc123").unwrap(), "'abc123'");
    }

    #[test]
    fn escape_literal_rejects_special_chars() {
        assert!(escape_literal("'; DROP TABLE--").is_err());
        assert!(escape_literal("tenant\x00id").is_err());
        assert!(escape_literal("tenant id").is_err()); // space
        assert!(escape_literal("tenant/id").is_err()); // slash
        assert!(escape_literal("{a,b}").is_err()); // braces
    }

    #[test]
    fn escape_set_value_allows_anything() {
        assert_eq!(escape_set_value("simple"), "'simple'");
        assert_eq!(escape_set_value("{a,b,c}"), "'{a,b,c}'");
        assert_eq!(escape_set_value("it's"), "'it''s'");
        assert_eq!(escape_set_value("a'b'c"), "'a''b''c'");
        assert_eq!(escape_set_value(""), "''");
    }

    #[test]
    fn quote_ident_valid() {
        assert_eq!(quote_ident("my_table").unwrap(), "\"my_table\"");
        assert_eq!(quote_ident("col1").unwrap(), "\"col1\"");
    }

    #[test]
    fn quote_ident_rejects_special_chars() {
        assert!(quote_ident("my table").is_err()); // space
        assert!(quote_ident("my-table").is_err()); // hyphen
        assert!(quote_ident("a;b").is_err()); // semicolon
    }

    // ─── Multiple messages in buffer ─────────────────────────────────────

    #[test]
    fn parse_multiple_backend_messages_from_single_buffer() {
        let mut buf = BytesMut::new();
        // Message 1: ReadyForQuery
        let msg1 = build_raw_backend_message(backend::READY_FOR_QUERY, &[b'I']);
        buf.extend_from_slice(&msg1);
        // Message 2: AuthOk
        let mut auth_payload = BytesMut::new();
        auth_payload.put_i32(auth::OK);
        let msg2 = build_raw_backend_message(backend::AUTHENTICATION, &auth_payload);
        buf.extend_from_slice(&msg2);

        let m1 = try_read_backend_message(&mut buf).unwrap();
        assert!(m1.is_ready_for_query());

        let m2 = try_read_backend_message(&mut buf).unwrap();
        assert!(m2.is_auth_ok());

        assert!(buf.is_empty());
    }
}
