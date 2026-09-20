// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The MSE Diffie-Hellman group: the 768-bit prime and generator 2.

use num_bigint::BigUint;

/// Public / shared key length in bytes.
pub const DH_KEY_LEN: usize = 96;

/// The MSE prime (RFC 2409 Oakley group 1, 768 bits).
const PRIME_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563";

fn prime() -> BigUint {
    BigUint::parse_bytes(PRIME_HEX.as_bytes(), 16).unwrap_or_default()
}

fn to_fixed(n: &BigUint) -> [u8; DH_KEY_LEN] {
    let bytes = n.to_bytes_be();
    let mut out = [0u8; DH_KEY_LEN];
    let n = bytes.len().min(DH_KEY_LEN);
    out[DH_KEY_LEN - n..].copy_from_slice(&bytes[bytes.len() - n..]);
    out
}

/// Our public key `2^private mod P` for a random `private`.
pub fn dh_public(private: &[u8]) -> [u8; DH_KEY_LEN] {
    let x = BigUint::from_bytes_be(private);
    to_fixed(&BigUint::from(2u32).modpow(&x, &prime()))
}

/// The shared secret `peer_public^private mod P`.
pub fn dh_secret(private: &[u8], peer_public: &[u8; DH_KEY_LEN]) -> [u8; DH_KEY_LEN] {
    let x = BigUint::from_bytes_be(private);
    let y = BigUint::from_bytes_be(peer_public);
    to_fixed(&y.modpow(&x, &prime()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exchange_agrees() {
        let a = [7u8; 20];
        let b = [9u8; 20];
        let ya = dh_public(&a);
        let yb = dh_public(&b);
        assert_ne!(ya, yb);
        assert_eq!(dh_secret(&a, &yb), dh_secret(&b, &ya));
        // Generator check: 2^1 = 2, right-aligned.
        let one = dh_public(&[1u8]);
        assert_eq!(one[DH_KEY_LEN - 1], 2);
        assert!(one[..DH_KEY_LEN - 1].iter().all(|b| *b == 0));
    }
}
