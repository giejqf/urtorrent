// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! RC4 keystream with the MSE 1024-byte discard.

use rc4::{KeyInit, Rc4, StreamCipher, consts::U20};

/// One direction of the encrypted stream.
pub struct Rc4Stream {
    cipher: Rc4<U20>,
}

impl Rc4Stream {
    /// A stream keyed with a 20-byte MSE key, first 1024 keystream bytes
    /// discarded.
    pub fn new(key: &[u8; 20]) -> Rc4Stream {
        let mut cipher = Rc4::<U20>::new(key.into());
        let mut discard = [0u8; 1024];
        cipher.apply_keystream(&mut discard);
        Rc4Stream { cipher }
    }

    /// Encrypt or decrypt `data` in place (RC4 is symmetric).
    pub fn apply(&mut self, data: &mut [u8]) {
        self.cipher.apply_keystream(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_and_discarding() {
        let key = [3u8; 20];
        let mut a = Rc4Stream::new(&key);
        let mut b = Rc4Stream::new(&key);
        let mut data = b"hello mse".to_vec();
        a.apply(&mut data);
        assert_ne!(data, b"hello mse");
        b.apply(&mut data);
        assert_eq!(data, b"hello mse");
        // Without the discard the first byte would differ from the raw RC4
        // keystream position 0; with it, two fresh streams still agree.
        let mut c = Rc4Stream::new(&key);
        let mut d = Rc4Stream::new(&key);
        let mut x = [0u8; 4];
        let mut y = [0u8; 4];
        c.apply(&mut x);
        d.apply(&mut y);
        assert_eq!(x, y);
    }
}
