use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

pub const ENV_VAR: &str = "QUICSSH_AUTH_SECRET";
pub const WINDOW_SECS: u64 = 30;
pub const TOKEN_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

pub fn secret_from_env() -> Option<Vec<u8>> {
    match std::env::var(ENV_VAR) {
        Ok(s) if !s.is_empty() => Some(s.into_bytes()),
        _ => None,
    }
}

pub fn current_window() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / WINDOW_SECS)
        .unwrap_or(0)
}

pub fn token_for_window(secret: &[u8], window: u64) -> [u8; TOKEN_LEN] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(b"quicssh-rs/v1");
    mac.update(&window.to_be_bytes());
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; TOKEN_LEN];
    out.copy_from_slice(&tag);
    out
}

/// Tokens that should be accepted right now (current ± 1 windows) to tolerate
/// clock skew up to ~WINDOW_SECS.
pub fn valid_tokens(secret: &[u8]) -> Vec<Vec<u8>> {
    let now = current_window();
    [now.wrapping_sub(1), now, now.wrapping_add(1)]
        .iter()
        .map(|w| token_for_window(secret, *w).to_vec())
        .collect()
}

/// Constant-time check that one of `offered` matches a token valid for the
/// current ±1 window range.
pub fn any_token_valid(secret: &[u8], offered: &[&[u8]]) -> bool {
    let valid = valid_tokens(secret);
    offered.iter().any(|o| {
        valid.iter().any(|v| {
            use subtle::ConstantTimeEq;
            v.len() == o.len() && v.ct_eq(o).into()
        })
    })
}

/// Extract the ALPN protocol list from a TLS ClientHello handshake message.
///
/// `bytes` should be the raw TLS handshake message (starting with the 1-byte
/// HandshakeType — `0x01` for ClientHello — followed by a 3-byte length and
/// the body). Returns `None` if the message is malformed, not a ClientHello,
/// or has no ALPN extension. Returns `Some(vec![])` if the ALPN extension is
/// present but empty.
pub fn parse_client_hello_alpn(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut r = Reader::new(bytes);
    if r.u8()? != 0x01 {
        return None; // not ClientHello
    }
    let body_len = r.u24()? as usize;
    let body = r.take(body_len)?;
    let mut r = Reader::new(body);

    let _legacy_version = r.take(2)?;
    let _random = r.take(32)?;
    let sid_len = r.u8()? as usize;
    r.take(sid_len)?;
    let cs_len = r.u16()? as usize;
    r.take(cs_len)?;
    let cm_len = r.u8()? as usize;
    r.take(cm_len)?;

    let ext_total = r.u16()? as usize;
    let ext_block = r.take(ext_total)?;
    let mut r = Reader::new(ext_block);
    while !r.is_empty() {
        let ty = r.u16()?;
        let ext_len = r.u16()? as usize;
        let ext_data = r.take(ext_len)?;
        if ty == 16 {
            // ALPN
            let mut a = Reader::new(ext_data);
            let list_len = a.u16()? as usize;
            let list = a.take(list_len)?;
            let mut a = Reader::new(list);
            let mut protos = Vec::new();
            while !a.is_empty() {
                let plen = a.u8()? as usize;
                let proto = a.take(plen)?;
                protos.push(proto.to_vec());
            }
            return Some(protos);
        }
    }
    None
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }
    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.buf.len() < n {
            return None;
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Option<u32> {
        let b = self.take(3)?;
        Some(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }
}
