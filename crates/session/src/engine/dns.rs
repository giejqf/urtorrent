// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Name resolution on a helper thread. `getaddrinfo` is blocking and not on
//! the data path (AGENTS.md 5.3), so it runs on `urt-dns` and completes ring
//! futures through the [`Bridge`].

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::mpsc::{Sender, channel};

use uring::NotifyHandle;

use uring::{Bridge, Completer};

type Result = io::Result<Vec<SocketAddr>>;

struct Job {
    host: String,
    port: u16,
    done: Completer<Result>,
}

/// The resolver.
pub struct Dns {
    bridge: Bridge<Result>,
    tx: Option<Sender<Job>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Dns {
    /// Start the helper thread.
    pub fn new(notify: NotifyHandle) -> Dns {
        let (tx, rx) = channel::<Job>();
        let thread = std::thread::Builder::new()
            .name("urt-dns".into())
            .spawn(move || {
                while let Ok(job) = rx.recv() {
                    let r = (job.host.as_str(), job.port)
                        .to_socket_addrs()
                        .map(|it| it.collect::<Vec<_>>());
                    job.done.complete(r);
                }
            })
            .ok();
        Dns {
            bridge: Bridge::new(notify),
            tx: Some(tx),
            thread,
        }
    }

    /// Resolve `host:port`. IP literals resolve without touching the thread.
    pub async fn resolve(&self, host: &str, port: u16) -> Result {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let (ticket, done) = self.bridge.ticket();
        let Some(tx) = &self.tx else {
            return Err(io::Error::other("resolver stopped"));
        };
        tx.send(Job {
            host: host.to_string(),
            port,
            done,
        })
        .map_err(|_| io::Error::other("resolver stopped"))?;
        ticket.await
    }

    /// Deliver finished lookups (call when the notifier fires).
    pub fn drain(&self) -> usize {
        self.bridge.drain()
    }
}

impl Drop for Dns {
    fn drop(&mut self) {
        self.tx.take();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
