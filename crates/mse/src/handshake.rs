// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The MSE handshake state machines.

use metainfo::InfoHash;
use profile::Rng;
use sha1::{Digest, Sha1};

use crate::Error;
use crate::dh::{DH_KEY_LEN, dh_public, dh_secret};
use crate::rc4s::Rc4Stream;

/// Pads are `random(512)`: 0..=512 bytes.
pub const MAX_PAD: usize = 512;
/// Length of the BitTorrent handshake carried as IA.
const IA_LEN: usize = 68;
const VC: [u8; 8] = [0; 8];

/// The stream key lookup found no torrent.
pub const SKEY_UNKNOWN: Error = Error::UnknownSkey;

/// Negotiated stream method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoMethod {
    /// Header obfuscation only; payload in the clear.
    Plaintext = 1,
    /// RC4 both ways.
    Rc4 = 2,
}

/// `crypto_provide` / allowed-level bitmask for the settings the caller
/// allows (`plaintext`, `rc4`).
pub fn allowed_mask(plaintext: bool, rc4: bool) -> u32 {
    (u32::from(plaintext)) | (u32::from(rc4) << 1)
}

/// The responder's method selection (libtorrent
/// `bt_peer_connection::on_receive`): intersect with what we allow, then keep
/// the least significant bit — or the most significant with `prefer_rc4`.
pub fn select(provided: u32, allowed: u32, prefer_rc4: bool) -> Option<CryptoMethod> {
    let both = provided & allowed & 0x3;
    if both == 0 {
        return None;
    }
    let bit = if prefer_rc4 {
        1u32 << (31 - both.leading_zeros())
    } else {
        both.isolate_lowest_one()
    };
    match bit {
        1 => Some(CryptoMethod::Plaintext),
        2 => Some(CryptoMethod::Rc4),
        _ => None,
    }
}

fn sha1(parts: &[&[u8]]) -> [u8; 20] {
    let mut h = Sha1::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn pad(rng: &mut dyn Rng) -> Vec<u8> {
    let n = rng.below(MAX_PAD as u32 + 1) as usize;
    let mut v = vec![0u8; n];
    for chunk in v.chunks_mut(4) {
        let r = rng.next_u32().to_le_bytes();
        chunk.copy_from_slice(&r[..chunk.len()]);
    }
    v
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// What a side observed of the other side's handshake (for captures and the
/// discriminator: the L2 items are method selection, `crypto_provide` /
/// `crypto_select` and the padding length distribution).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Observed {
    /// Length of the pad after the peer's DH key (PadA seen by the responder,
    /// PadB seen by the initiator).
    pub pad_after_key: Option<usize>,
    /// PadC (seen by the responder) or PadD (seen by the initiator).
    pub pad_crypto: Option<usize>,
    /// The peer's `crypto_provide` (responder) or `crypto_select` (initiator).
    pub crypto_field: Option<u32>,
    /// `len(IA)` the initiator announced (responder only).
    pub ia_len: Option<usize>,
}

/// The result of a completed handshake.
pub struct Outcome {
    /// Negotiated method.
    pub method: CryptoMethod,
    /// The torrent (the responder learns it from the stream key).
    pub info_hash: InfoHash,
    /// Encrypt outgoing payload with this (RC4 only).
    pub encrypt: Option<Rc4Stream>,
    /// Decrypt incoming payload with this (RC4 only).
    pub decrypt: Option<Rc4Stream>,
    /// Plaintext already available: the responder gets the peer's IA (its
    /// BitTorrent handshake) plus any following bytes; the initiator gets
    /// whatever followed pe4.
    pub plaintext: Vec<u8>,
    /// What the peer's side of the handshake looked like.
    pub observed: Observed,
}

enum IState {
    WaitYb,
    /// Searching for the encrypted VC (skipping PadB).
    WaitVc,
    /// VC found and consumed; reading select + len(PadD) (6 bytes).
    WaitSelect,
    /// Skipping PadD.
    WaitPadD {
        method: CryptoMethod,
        remaining: usize,
    },
}

/// The connecting side.
pub struct Initiator {
    info_hash: InfoHash,
    private: [u8; 20],
    provide: u32,
    allowed: u32,
    ia: Vec<u8>,
    state: IState,
    buf: Vec<u8>,
    out: Vec<u8>,
    encrypt: Option<Rc4Stream>,
    decrypt: Option<Rc4Stream>,
    vc_marker: [u8; 8],
    observed: Observed,
}

impl Initiator {
    /// Start: `private` is 20 random bytes (the DH exponent), `ia` the 68-byte
    /// BitTorrent handshake to carry inside the crypto handshake, `allowed`
    /// the method mask we accept (also sent as `crypto_provide`).
    pub fn new(
        info_hash: InfoHash,
        private: [u8; 20],
        ia: Vec<u8>,
        allowed: u32,
        rng: &mut dyn Rng,
    ) -> Initiator {
        let mut out = dh_public(&private).to_vec();
        out.extend_from_slice(&pad(rng));
        let provide = if allowed & 0x3 == 0 {
            0x3
        } else {
            allowed & 0x3
        };
        Initiator {
            info_hash,
            private,
            provide,
            allowed: provide,
            ia,
            state: IState::WaitYb,
            buf: Vec::new(),
            out,
            encrypt: None,
            decrypt: None,
            vc_marker: [0; 8],
            observed: Observed::default(),
        }
    }

    /// Bytes to send.
    pub fn take_outbound(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    /// Feed received bytes; `Some(outcome)` once the handshake completes.
    pub fn receive(&mut self, bytes: &[u8], rng: &mut dyn Rng) -> Result<Option<Outcome>, Error> {
        self.buf.extend_from_slice(bytes);
        loop {
            match self.state {
                IState::WaitYb => {
                    if self.buf.len() < DH_KEY_LEN {
                        return Ok(None);
                    }
                    let mut yb = [0u8; DH_KEY_LEN];
                    yb.copy_from_slice(&self.buf[..DH_KEY_LEN]);
                    self.buf.drain(..DH_KEY_LEN);
                    let s = dh_secret(&self.private, &yb);
                    let req1 = sha1(&[b"req1", &s]);
                    let req2 = sha1(&[b"req2", &self.info_hash]);
                    let req3 = sha1(&[b"req3", &s]);
                    let mut enc = Rc4Stream::new(&sha1(&[b"keyA", &s, &self.info_hash]));
                    let key_b = sha1(&[b"keyB", &s, &self.info_hash]);
                    let dec = Rc4Stream::new(&key_b);
                    // The encrypted VC the responder will send: keystream ^ 0,
                    // computed on a separate stream so `dec` stays aligned.
                    let mut marker = VC;
                    Rc4Stream::new(&key_b).apply(&mut marker);
                    self.vc_marker = marker;
                    let padc = pad(rng);
                    let mut body = Vec::with_capacity(8 + 4 + 2 + padc.len() + 2 + self.ia.len());
                    body.extend_from_slice(&VC);
                    body.extend_from_slice(&self.provide.to_be_bytes());
                    body.extend_from_slice(&(padc.len() as u16).to_be_bytes());
                    body.extend_from_slice(&padc);
                    body.extend_from_slice(&(self.ia.len() as u16).to_be_bytes());
                    body.extend_from_slice(&self.ia);
                    enc.apply(&mut body);
                    self.out.extend_from_slice(&req1);
                    let mut x = req2;
                    for (a, b) in x.iter_mut().zip(req3.iter()) {
                        *a ^= b;
                    }
                    self.out.extend_from_slice(&x);
                    self.out.extend_from_slice(&body);
                    self.encrypt = Some(enc);
                    self.decrypt = Some(dec);
                    self.state = IState::WaitVc;
                }
                IState::WaitVc => {
                    let Some(pos) = find(&self.buf, &self.vc_marker) else {
                        if self.buf.len() > MAX_PAD + 8 {
                            return Err(Error::Sync);
                        }
                        return Ok(None);
                    };
                    if pos > MAX_PAD {
                        return Err(Error::Sync);
                    }
                    // Consume PadB + the encrypted VC; the keystream advances
                    // over the VC.
                    self.observed.pad_after_key = Some(pos);
                    let mut vc = self.buf[pos..pos + 8].to_vec();
                    self.decrypt.as_mut().ok_or(Error::Sync)?.apply(&mut vc);
                    self.buf.drain(..pos + 8);
                    self.state = IState::WaitSelect;
                }
                IState::WaitSelect => {
                    if self.buf.len() < 6 {
                        return Ok(None);
                    }
                    let mut head = self.buf[..6].to_vec();
                    self.decrypt.as_mut().ok_or(Error::Sync)?.apply(&mut head);
                    self.buf.drain(..6);
                    let sel = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
                    let pad_len = u16::from_be_bytes([head[4], head[5]]) as usize;
                    self.observed.crypto_field = Some(sel);
                    self.observed.pad_crypto = Some(pad_len);
                    if pad_len > MAX_PAD {
                        return Err(Error::Length);
                    }
                    let method = match sel & self.allowed {
                        1 => CryptoMethod::Plaintext,
                        2 => CryptoMethod::Rc4,
                        _ => return Err(Error::NoMethod),
                    };
                    self.state = IState::WaitPadD {
                        method,
                        remaining: pad_len,
                    };
                }
                IState::WaitPadD { method, remaining } => {
                    if self.buf.len() < remaining {
                        return Ok(None);
                    }
                    let mut padd = self.buf[..remaining].to_vec();
                    self.decrypt.as_mut().ok_or(Error::Sync)?.apply(&mut padd);
                    self.buf.drain(..remaining);
                    let mut rest = std::mem::take(&mut self.buf);
                    let (encrypt, decrypt) = match method {
                        CryptoMethod::Rc4 => {
                            let mut dec = self.decrypt.take();
                            if let Some(d) = dec.as_mut() {
                                d.apply(&mut rest);
                            }
                            (self.encrypt.take(), dec)
                        }
                        CryptoMethod::Plaintext => (None, None),
                    };
                    return Ok(Some(Outcome {
                        method,
                        info_hash: self.info_hash,
                        encrypt,
                        decrypt,
                        plaintext: rest,
                        observed: self.observed,
                    }));
                }
            }
        }
    }
}

enum RState {
    WaitYa,
    WaitReq1,
    /// req2 ^ req3 (20 bytes): resolves the torrent, keys the streams.
    WaitReq2,
    /// RC4_A(vc 8, provide 4, len(PadC) 2).
    WaitHead,
    /// Skipping PadC (encrypted).
    WaitPadC {
        provide: u32,
        remaining: usize,
    },
    /// len(IA) (2 bytes, encrypted).
    WaitIaLen {
        provide: u32,
    },
    /// IA (encrypted): the peer's BitTorrent handshake.
    WaitIa {
        provide: u32,
        remaining: usize,
    },
}

/// The accepting side.
pub struct Responder {
    private: [u8; 20],
    allowed: u32,
    prefer_rc4: bool,
    state: RState,
    buf: Vec<u8>,
    out: Vec<u8>,
    secret: [u8; DH_KEY_LEN],
    req1: [u8; 20],
    info_hash: InfoHash,
    dec: Option<Rc4Stream>,
    observed: Observed,
}

impl Responder {
    /// Start with our 20 random DH bytes and the methods we allow.
    pub fn new(private: [u8; 20], allowed: u32, prefer_rc4: bool) -> Responder {
        Responder {
            private,
            allowed: allowed & 0x3,
            prefer_rc4,
            state: RState::WaitYa,
            buf: Vec::new(),
            out: Vec::new(),
            secret: [0; DH_KEY_LEN],
            req1: [0; 20],
            info_hash: [0; 20],
            dec: None,
            observed: Observed::default(),
        }
    }

    fn decrypt_take(&mut self, n: usize) -> Result<Vec<u8>, Error> {
        let mut bytes: Vec<u8> = self.buf.drain(..n).collect();
        self.dec.as_mut().ok_or(Error::Sync)?.apply(&mut bytes);
        Ok(bytes)
    }

    /// Bytes to send.
    pub fn take_outbound(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    /// Feed received bytes. `torrents` are the info-hashes we serve (to
    /// resolve the stream key). `Some(outcome)` once complete; the outcome's
    /// `plaintext` starts with the peer's BitTorrent handshake (IA).
    pub fn receive(
        &mut self,
        bytes: &[u8],
        torrents: &[InfoHash],
        rng: &mut dyn Rng,
    ) -> Result<Option<Outcome>, Error> {
        self.buf.extend_from_slice(bytes);
        loop {
            match self.state {
                RState::WaitYa => {
                    if self.buf.len() < DH_KEY_LEN {
                        return Ok(None);
                    }
                    let mut ya = [0u8; DH_KEY_LEN];
                    ya.copy_from_slice(&self.buf[..DH_KEY_LEN]);
                    self.buf.drain(..DH_KEY_LEN);
                    self.secret = dh_secret(&self.private, &ya);
                    self.req1 = sha1(&[b"req1", &self.secret]);
                    self.out.extend_from_slice(&dh_public(&self.private));
                    self.out.extend_from_slice(&pad(rng));
                    self.state = RState::WaitReq1;
                }
                RState::WaitReq1 => {
                    let Some(pos) = find(&self.buf, &self.req1) else {
                        if self.buf.len() > MAX_PAD + 20 {
                            return Err(Error::Sync);
                        }
                        return Ok(None);
                    };
                    if pos > MAX_PAD {
                        return Err(Error::Sync);
                    }
                    self.observed.pad_after_key = Some(pos);
                    self.buf.drain(..pos + 20);
                    self.state = RState::WaitReq2;
                }
                RState::WaitReq2 => {
                    if self.buf.len() < 20 {
                        return Ok(None);
                    }
                    let req3 = sha1(&[b"req3", &self.secret]);
                    let mut req2 = [0u8; 20];
                    for i in 0..20 {
                        req2[i] = self.buf[i] ^ req3[i];
                    }
                    self.buf.drain(..20);
                    let info_hash = torrents
                        .iter()
                        .copied()
                        .find(|ih| sha1(&[b"req2", ih]) == req2)
                        .ok_or(Error::UnknownSkey)?;
                    self.info_hash = info_hash;
                    self.dec = Some(Rc4Stream::new(&sha1(&[b"keyA", &self.secret, &info_hash])));
                    self.state = RState::WaitHead;
                }
                RState::WaitHead => {
                    if self.buf.len() < 14 {
                        return Ok(None);
                    }
                    let head = self.decrypt_take(14)?;
                    if head[..8] != VC {
                        return Err(Error::Sync);
                    }
                    let provide = u32::from_be_bytes([head[8], head[9], head[10], head[11]]);
                    let padc = u16::from_be_bytes([head[12], head[13]]) as usize;
                    self.observed.crypto_field = Some(provide);
                    self.observed.pad_crypto = Some(padc);
                    if padc > MAX_PAD {
                        return Err(Error::Length);
                    }
                    self.state = RState::WaitPadC {
                        provide,
                        remaining: padc,
                    };
                }
                RState::WaitPadC { provide, remaining } => {
                    if self.buf.len() < remaining {
                        return Ok(None);
                    }
                    let _pad = self.decrypt_take(remaining)?;
                    self.state = RState::WaitIaLen { provide };
                }
                RState::WaitIaLen { provide } => {
                    if self.buf.len() < 2 {
                        return Ok(None);
                    }
                    let len = self.decrypt_take(2)?;
                    let ia_len = u16::from_be_bytes([len[0], len[1]]) as usize;
                    self.observed.ia_len = Some(ia_len);
                    if ia_len > IA_LEN {
                        return Err(Error::Length);
                    }
                    self.state = RState::WaitIa {
                        provide,
                        remaining: ia_len,
                    };
                }
                RState::WaitIa { provide, remaining } => {
                    if self.buf.len() < remaining {
                        return Ok(None);
                    }
                    let mut plaintext = self.decrypt_take(remaining)?;
                    let method =
                        select(provide, self.allowed, self.prefer_rc4).ok_or(Error::NoMethod)?;
                    let mut rest = std::mem::take(&mut self.buf);
                    // pe4: RC4_B(vc, select, len(padD), padD)
                    let mut enc = Rc4Stream::new(&sha1(&[b"keyB", &self.secret, &self.info_hash]));
                    let padd = pad(rng);
                    let mut pe4 = Vec::with_capacity(14 + padd.len());
                    pe4.extend_from_slice(&VC);
                    pe4.extend_from_slice(&(method as u32).to_be_bytes());
                    pe4.extend_from_slice(&(padd.len() as u16).to_be_bytes());
                    pe4.extend_from_slice(&padd);
                    enc.apply(&mut pe4);
                    self.out.extend_from_slice(&pe4);
                    let (encrypt, decrypt) = match method {
                        CryptoMethod::Rc4 => {
                            let mut dec = self.dec.take();
                            if let Some(d) = dec.as_mut() {
                                d.apply(&mut rest);
                            }
                            plaintext.append(&mut rest);
                            (Some(enc), dec)
                        }
                        CryptoMethod::Plaintext => {
                            plaintext.append(&mut rest);
                            (None, None)
                        }
                    };
                    return Ok(Some(Outcome {
                        method,
                        info_hash: self.info_hash,
                        encrypt,
                        decrypt,
                        plaintext,
                        observed: self.observed,
                    }));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Lcg(u64);
    impl Rng for Lcg {
        fn next_u32(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) as u32
        }
    }

    fn run(allowed_i: u32, allowed_r: u32, prefer_rc4: bool, chunk: usize) -> (Outcome, Outcome) {
        let ih = [0x42u8; 20];
        let ia = vec![0x13u8; 68];
        let mut ri = Lcg(1);
        let mut rr = Lcg(2);
        let mut init = Initiator::new(ih, [5u8; 20], ia.clone(), allowed_i, &mut ri);
        let mut resp = Responder::new([6u8; 20], allowed_r, prefer_rc4);
        let torrents = [[1u8; 20], ih];
        let mut a_to_b = init.take_outbound();
        let mut b_to_a: Vec<u8> = Vec::new();
        let mut out_i = None;
        let mut out_r = None;
        // Trailing payload after each side's handshake, to test the
        // continuation of the streams.
        for _ in 0..5000 {
            if out_r.is_none() {
                let take = a_to_b.len().min(chunk);
                let piece: Vec<u8> = a_to_b.drain(..take).collect();
                if let Some(o) = resp.receive(&piece, &torrents, &mut rr).unwrap() {
                    out_r = Some(o);
                }
                b_to_a.extend(resp.take_outbound());
            }
            if out_i.is_none() {
                let take = b_to_a.len().min(chunk);
                let piece: Vec<u8> = b_to_a.drain(..take).collect();
                if let Some(o) = init.receive(&piece, &mut ri).unwrap() {
                    out_i = Some(o);
                }
                a_to_b.extend(init.take_outbound());
            }
            if out_i.is_some() && out_r.is_some() {
                break;
            }
        }
        (
            out_i.expect("initiator done"),
            out_r.expect("responder done"),
        )
    }

    #[test]
    fn rc4_roundtrip_in_small_chunks() {
        for chunk in [1usize, 7, 64, 4096] {
            let (mut i, mut r) = run(3, 3, true, chunk);
            assert_eq!(i.method, CryptoMethod::Rc4);
            assert_eq!(r.method, CryptoMethod::Rc4);
            assert_eq!(r.info_hash, [0x42; 20]);
            assert_eq!(
                r.plaintext,
                vec![0x13u8; 68],
                "IA delivered to the responder"
            );
            assert!(i.plaintext.is_empty());
            assert_eq!(r.observed.crypto_field, Some(3));
            assert_eq!(r.observed.ia_len, Some(68));
            assert_eq!(i.observed.crypto_field, Some(2));
            assert!(r.observed.pad_after_key.is_some_and(|p| p <= MAX_PAD));
            assert!(i.observed.pad_crypto.is_some_and(|p| p <= MAX_PAD));
            // Streams continue symmetrically.
            let mut msg = b"payload after handshake".to_vec();
            i.encrypt.as_mut().unwrap().apply(&mut msg);
            r.decrypt.as_mut().unwrap().apply(&mut msg);
            assert_eq!(msg, b"payload after handshake");
            let mut back = b"reply".to_vec();
            r.encrypt.as_mut().unwrap().apply(&mut back);
            i.decrypt.as_mut().unwrap().apply(&mut back);
            assert_eq!(back, b"reply");
        }
    }

    #[test]
    fn plaintext_selected_without_prefer_rc4() {
        let (i, r) = run(3, 3, false, 1024);
        assert_eq!(i.method, CryptoMethod::Plaintext);
        assert_eq!(r.method, CryptoMethod::Plaintext);
        assert!(i.encrypt.is_none() && r.decrypt.is_none());
        assert_eq!(r.plaintext, vec![0x13u8; 68]);
    }

    #[test]
    fn selection_rules() {
        assert_eq!(select(3, 3, false), Some(CryptoMethod::Plaintext));
        assert_eq!(select(3, 3, true), Some(CryptoMethod::Rc4));
        assert_eq!(select(2, 3, false), Some(CryptoMethod::Rc4));
        assert_eq!(select(1, 2, true), None);
        assert_eq!(select(3, 2, false), Some(CryptoMethod::Rc4));
        assert_eq!(allowed_mask(true, false), 1);
        assert_eq!(allowed_mask(true, true), 3);
    }

    #[test]
    fn unknown_torrent_and_garbage_fail_cleanly() {
        let mut rr = Lcg(3);
        let mut resp = Responder::new([6u8; 20], 3, true);
        let mut ri = Lcg(4);
        let mut init = Initiator::new([9u8; 20], [5u8; 20], vec![0; 68], 3, &mut ri);
        let ya = init.take_outbound();
        assert!(resp.receive(&ya, &[[1u8; 20]], &mut rr).unwrap().is_none());
        let yb = resp.take_outbound();
        assert!(init.receive(&yb, &mut ri).unwrap().is_none());
        let pe3 = init.take_outbound();
        assert!(matches!(
            resp.receive(&pe3, &[[1u8; 20]], &mut rr),
            Err(Error::UnknownSkey)
        ));
        // Garbage instead of a handshake never syncs.
        let mut resp = Responder::new([6u8; 20], 3, true);
        let junk = vec![0xAAu8; 96 + 600];
        assert!(matches!(
            resp.receive(&junk, &[[1u8; 20]], &mut rr),
            Err(Error::Sync)
        ));
    }
}
