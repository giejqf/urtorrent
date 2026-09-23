// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! TLS for HTTPS trackers (ADR 0003): rustls through its buffer-in /
//! buffer-out API, so ciphertext still moves over io_uring sockets. Roots are
//! Mozilla's (`webpki-roots`) plus any PEM the caller supplied (the test CA in
//! the lab) and `SSL_CERT_FILE` if set. Certificates are always validated;
//! SNI is sent; no ALPN (the oracle offers none for tracker connections —
//! UNVERIFIED until the HTTPS capture is inspected at the TLS layer, which is
//! out of the discriminator's scope anyway).

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use uring::{Buffer, TcpStream};

/// Shared client configuration.
pub struct TlsClient {
    config: Arc<rustls::ClientConfig>,
}

impl TlsClient {
    /// Build from Mozilla roots plus `extra_roots` (PEM bundles).
    pub fn new(extra_roots: &[Vec<u8>]) -> Result<TlsClient, String> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for pem in extra_roots {
            for cert in pem_certs(pem)? {
                roots
                    .add(cert)
                    .map_err(|e| format!("bad CA certificate: {e}"))?;
            }
        }
        // Explicit provider (ADR 0003): never rely on the process default,
        // which is ambiguous when another crate in the build enables `ring`.
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("tls versions: {e}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(TlsClient {
            config: Arc::new(config),
        })
    }

    /// Roots from `SSL_CERT_FILE`, if the variable names a readable file.
    pub fn env_roots() -> Vec<Vec<u8>> {
        std::env::var_os("SSL_CERT_FILE")
            .and_then(|p| std::fs::read(p).ok())
            .into_iter()
            .collect()
    }
}

/// The certificates of a PEM bundle; other sections (keys, parameters) and
/// text around them are skipped, a malformed certificate is an error.
fn pem_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    CertificateDer::pem_slice_iter(pem)
        .map(|c| c.map_err(|e| format!("bad CA pem: {e}")))
        .collect()
}

/// A TLS session over a uring TCP stream.
pub struct TlsStream {
    tcp: TcpStream,
    conn: rustls::ClientConnection,
    eof: bool,
}

impl TlsStream {
    /// Run the handshake against `server_name` on an already-connected socket.
    pub async fn connect(
        client: &TlsClient,
        tcp: TcpStream,
        server_name: &str,
    ) -> Result<TlsStream, String> {
        let name = ServerName::try_from(server_name.to_string())
            .map_err(|e| format!("bad server name {server_name}: {e}"))?;
        let conn = rustls::ClientConnection::new(client.config.clone(), name)
            .map_err(|e| format!("tls: {e}"))?;
        let mut s = TlsStream {
            tcp,
            conn,
            eof: false,
        };
        while s.conn.is_handshaking() {
            s.flush().await?;
            if s.conn.is_handshaking() && s.conn.wants_read() {
                s.read_records().await?;
                if s.eof {
                    return Err("tls: connection closed during handshake".into());
                }
            }
        }
        s.flush().await?;
        Ok(s)
    }

    /// Push queued TLS records to the socket.
    async fn flush(&mut self) -> Result<(), String> {
        while self.conn.wants_write() {
            let mut out = Vec::with_capacity(16 * 1024);
            self.conn
                .write_tls(&mut out)
                .map_err(|e| format!("tls write: {e}"))?;
            if out.is_empty() {
                break;
            }
            self.tcp
                .send_all(Buffer::from_vec(out))
                .await
                .map_err(|e| format!("send: {e}"))?;
        }
        Ok(())
    }

    /// Read one batch of TLS records from the socket and process them.
    async fn read_records(&mut self) -> Result<(), String> {
        let (r, buf) = self
            .tcp
            .recv(Buffer::from_vec(vec![0u8; 16 * 1024 + 512]))
            .await;
        match r {
            Ok(0) => {
                self.eof = true;
                Ok(())
            }
            Ok(_) => {
                let mut cursor = std::io::Cursor::new(buf.as_slice());
                self.conn
                    .read_tls(&mut cursor)
                    .map_err(|e| format!("tls read: {e}"))?;
                self.conn
                    .process_new_packets()
                    .map_err(|e| format!("tls: {e}"))?;
                Ok(())
            }
            Err(e) => Err(format!("recv: {e}")),
        }
    }

    /// Send plaintext.
    pub async fn send_all(&mut self, data: &[u8]) -> Result<(), String> {
        self.conn
            .writer()
            .write_all(data)
            .map_err(|e| format!("tls: {e}"))?;
        self.flush().await
    }

    /// Receive plaintext (up to `max` bytes). An empty result means the peer
    /// closed the connection.
    pub async fn recv(&mut self, max: usize) -> Result<Vec<u8>, String> {
        loop {
            let mut out = vec![0u8; max];
            match self.conn.reader().read(&mut out) {
                Ok(n) if n > 0 => {
                    out.truncate(n);
                    return Ok(out);
                }
                Ok(_) => return Ok(Vec::new()), // clean close_notify
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(Vec::new()),
                Err(e) => return Err(format!("tls: {e}")),
            }
            if self.eof {
                return Ok(Vec::new());
            }
            self.flush().await?;
            self.read_records().await?;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// A self-signed test CA (P-256, valid until 2126).
    const CA: &str = "\
-----BEGIN CERTIFICATE-----
MIIBjzCCATWgAwIBAgIUUTs5zcSzVlQhTmwFwuJUUktDPwgwCgYIKoZIzj0EAwIw
HDEaMBgGA1UEAwwRdXJ0b3JyZW50IHRlc3QgQ0EwIBcNMjYwOTIzMDY0MTUzWhgP
MjEyNjA4MzAwNjQxNTNaMBwxGjAYBgNVBAMMEXVydG9ycmVudCB0ZXN0IENBMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERnnEl6iXl3muXkJEthwXy6fjQOvVtGes
qiUjnjSKJRxL5fb1bTW0GhJZz4Qxw1U7px61laU85uvX6DVyLz2poqNTMFEwHQYD
VR0OBBYEFOnh1DhyGtFfiFjp9Kwhb8Fltod/MB8GA1UdIwQYMBaAFOnh1DhyGtFf
iFjp9Kwhb8Fltod/MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIh
AJ/pt6Y1VuBTuHJGORuymlCrt76UdWryvC08jklxxkEXAiBnwyFfcvrEi7mMT63o
bjoTPMwadd7Fylj3pQ4roKgdIg==
-----END CERTIFICATE-----
";

    #[test]
    fn a_bundle_yields_its_certificates_and_skips_the_rest() {
        let bundle = format!(
            "a CA bundle\n-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n{CA}{CA}"
        );
        assert_eq!(pem_certs(bundle.as_bytes()).unwrap().len(), 2);
        assert!(pem_certs(b"no pem here").unwrap().is_empty());
        assert!(TlsClient::new(&[CA.as_bytes().to_vec()]).is_ok());
    }

    #[test]
    fn a_malformed_certificate_is_refused() {
        let broken = CA.replacen("MIIB", "M!!B", 1);
        let err = pem_certs(broken.as_bytes()).err().unwrap();
        assert!(err.starts_with("bad CA pem"), "{err}");
        assert!(TlsClient::new(&[broken.into_bytes()]).is_err());
    }
}
