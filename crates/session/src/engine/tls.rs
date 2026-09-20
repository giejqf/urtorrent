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
            let mut cursor = std::io::Cursor::new(pem);
            for cert in rustls_pemfile::certs(&mut cursor) {
                let cert: CertificateDer<'static> = cert.map_err(|e| format!("bad CA pem: {e}"))?;
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
