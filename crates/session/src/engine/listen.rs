// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Listen sockets, the DHT node and the identity profile changed while the
//! session runs (libtorrent `reopen_listen_sockets` / `apply_settings`):
//! what the frontend's preferences page needs without a session rebuild.
//!
//! Every change that trackers can see is announced honestly: torrents send
//! `stopped` under the old port / identity first, then `started` under the
//! new one, so a tracker never keeps a ghost peer (AGENTS.md rule 1 and Q9's
//! per-listen-socket announce state). Established TCP connections are
//! independent of the listen sockets and stay; uTP connections were bound
//! to the replaced UDP sockets and are dropped, as libtorrent does.

use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::rc::Rc;
use std::time::{Duration, Instant};

use uring::TcpListener;

use super::local::{Either, Flag, select2};
use super::torrent::Torrent;
use super::{Ctx, Error, http, lsd, peer, transport, utp};

/// TCP listen sockets bound for one configuration.
pub struct Bound {
    pub listeners: Vec<TcpListener>,
    /// The port in use (the kernel's choice when 0 was asked).
    pub port: u16,
    pub families: http::Families,
    /// The addresses that actually bound.
    pub v4: Option<Ipv4Addr>,
    pub v6: Option<Ipv6Addr>,
}

/// Bind the TCP listen sockets: one per configured family, `IPV6_V6ONLY`
/// on the v6 one, the v6 socket on the port the v4 one got when the port
/// was 0. A host without IPv6 is fine as long as IPv4 bound; nothing
/// binding is an error.
pub fn bind_tcp(port: u16, v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> Result<Bound, Error> {
    let mut listeners: Vec<TcpListener> = Vec::new();
    let mut port = port;
    let mut bind_err: Option<uring::Error> = None;
    let mut bound_v4 = None;
    let mut bound_v6 = None;
    if let Some(a) = v4 {
        match TcpListener::bind(SocketAddr::new(IpAddr::V4(a), port)) {
            Ok(l) => {
                port = l.local_addr().port();
                listeners.push(l);
                bound_v4 = Some(a);
            }
            Err(e) => bind_err = Some(e),
        }
    }
    if let Some(a) = v6 {
        match TcpListener::bind(SocketAddr::new(IpAddr::V6(a), port)) {
            Ok(l) => {
                port = l.local_addr().port();
                listeners.push(l);
                bound_v6 = Some(a);
            }
            Err(e) => {
                if listeners.is_empty() {
                    bind_err = Some(e);
                } else {
                    tracing::warn!("ipv6 listen failed: {e}");
                }
            }
        }
    }
    if listeners.is_empty() {
        return Err(bind_err.map_or_else(
            || Error::Io("no listen address configured".into()),
            Error::from,
        ));
    }
    Ok(Bound {
        families: http::Families {
            v4: bound_v4.is_some(),
            v6: bound_v6.is_some(),
        },
        listeners,
        port,
        v4: bound_v4,
        v6: bound_v6,
    })
}

/// Run an accept loop for `listener`, counted so a listen change can wait
/// for the old sockets to close before binding the same port again.
pub fn spawn_accept(ctx: &Rc<Ctx>, listener: TcpListener, generation: Rc<Flag>) {
    ctx.accept_loops.set(ctx.accept_loops.get() + 1);
    let ctx2 = ctx.clone();
    uring::spawn(async move {
        accept_loop(ctx2.clone(), listener, generation).await;
        ctx2.accept_loops.set(ctx2.accept_loops.get() - 1);
    });
}

/// Accept peers on `listener` until the session closes or the listen
/// sockets are replaced (`generation`); the listener closes on exit.
async fn accept_loop(ctx: Rc<Ctx>, listener: TcpListener, generation: Rc<Flag>) {
    loop {
        match select2(
            listener.accept(),
            select2(ctx.closing.wait(), generation.wait()),
        )
        .await
        {
            Either::Left(Ok(stream)) => {
                if !ctx.transports().tcp_incoming() {
                    // libtorrent accepts and drops (`enable_incoming_tcp`).
                    drop(stream);
                    continue;
                }
                uring::spawn(peer::run_incoming(
                    ctx.clone(),
                    transport::Transport::Tcp(stream),
                ));
            }
            Either::Left(Err(e)) => {
                tracing::warn!("accept failed: {e}");
                uring::sleep(Duration::from_millis(100)).await;
            }
            Either::Right(_) => break,
        }
    }
}

/// Route incoming uTP connections (SYNs the demultiplexer accepted) to the
/// peer code.
pub fn install_utp(ctx: &Rc<Ctx>, host: Rc<utp::UtpHost>) {
    let weak = Rc::downgrade(ctx);
    ctx.udp.set_utp(
        host,
        Box::new(move |key| {
            if let Some(ctx) = weak.upgrade()
                && let Some(h) = ctx.utp()
            {
                uring::spawn(peer::run_incoming(
                    ctx.clone(),
                    transport::Transport::Utp(Rc::new(h.stream(key))),
                ));
            }
        }),
    );
}

/// The torrents currently announcing, after their `stopped` announces have
/// gone out under the port and identity in force at the call (each bounded
/// to ten seconds). The announcers are left stopped; `restart_announces`
/// starts them again once the change is in place.
async fn announce_stopped_all(ctx: &Rc<Ctx>) -> Vec<Rc<RefCell<Torrent>>> {
    let torrents: Vec<Rc<RefCell<Torrent>>> = ctx.torrents.borrow().values().cloned().collect();
    let mut running = Vec::new();
    let mut handles = Vec::new();
    for t in torrents {
        let jobs = {
            let mut tb = t.borrow_mut();
            if !tb.tasks_running || tb.closing.is_set() || tb.paused {
                continue;
            }
            tb.announcer.stop()
        };
        for job in jobs {
            let ctx2 = ctx.clone();
            let t2 = t.clone();
            handles.push(uring::spawn(async move {
                let _ = uring::timeout(
                    Duration::from_secs(10),
                    super::tracker_task::announce_once(&ctx2, &t2, job),
                )
                .await;
            }));
        }
        running.push(t);
    }
    for h in handles {
        h.await;
    }
    running
}

/// Start announcing again under the new port / identity: fresh endpoint
/// state per listen socket, `started` on the next tracker round, the DHT
/// and LSD told.
fn restart_announces(ctx: &Rc<Ctx>, torrents: &[Rc<RefCell<Torrent>>]) {
    let endpoints = ctx.families().endpoints().len();
    for t in torrents {
        {
            let mut tb = t.borrow_mut();
            if tb.closing.is_set() || !tb.tasks_running {
                continue;
            }
            tb.announcer.reset_endpoints(endpoints);
            tb.announcer.start();
            tb.tracker_kick.notify();
            if let Some(d) = ctx.dht()
                && !tb.private
            {
                d.announce_soon(tb.id);
            }
        }
        lsd::announce_now(ctx, t);
    }
}

/// `Session::set_listen`: bind first (a failure leaves everything as it
/// was), announce `stopped` on the old sockets, swap the TCP listeners, the
/// UDP sockets (the DHT node carries on over them; uTP connections drop),
/// the LSD sockets and the address facts, drop peers of a family that went
/// away, then announce `started` on the new sockets. Returns the port in
/// use.
pub async fn set_listen(
    ctx: &Rc<Ctx>,
    port: u16,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
) -> Result<u16, Error> {
    let same_port = port != 0 && port == ctx.listen_port();
    // A new port binds before anything is touched, so a failure changes
    // nothing. Keeping the port (addresses change) means the old sockets
    // must close first; if the bind then fails the old configuration is
    // put back.
    let bound = if same_port {
        None
    } else {
        Some(bind_tcp(port, v4, v6)?)
    };
    let running = announce_stopped_all(ctx).await;
    let old_cfg = (ctx.listen_port(), ctx.listen_v4(), ctx.listen_v6());
    let bound = match bound {
        Some(b) => {
            retire_listeners(ctx).await;
            b
        }
        None => {
            retire_listeners(ctx).await;
            match bind_tcp(port, v4, v6) {
                Ok(b) => b,
                Err(e) => {
                    // Best effort: the old sockets again.
                    match bind_tcp(old_cfg.0, old_cfg.1, old_cfg.2) {
                        Ok(b) => {
                            let generation = ctx.listen_gen();
                            for l in b.listeners {
                                spawn_accept(ctx, l, generation.clone());
                            }
                            restart_announces(ctx, &running);
                        }
                        Err(e2) => tracing::error!("listen sockets lost: {e2}"),
                    }
                    return Err(e);
                }
            }
        }
    };
    let generation = ctx.listen_gen();
    for l in bound.listeners {
        spawn_accept(ctx, l, generation.clone());
    }
    ctx.listen_port.set(bound.port);
    ctx.families.set(bound.families);
    ctx.listen_v4.set(bound.v4);
    ctx.listen_v6.set(bound.v6);
    // UDP: trackers, DHT and uTP share the listen port's sockets.
    let udp_ok = ctx.udp.rebind(bound.port, bound.v4, bound.v6).await;
    if let Some(h) = ctx.utp() {
        h.abort_all();
    }
    if udp_ok && ctx.utp().is_none() {
        let host = utp::UtpHost::new(
            utp::default_config(),
            ctx.udp.clone(),
            ctx.rng.clone(),
            ctx.transports().utp_incoming(),
            ctx.max_connections().max(1) * 2,
        );
        install_utp(ctx, host.clone());
        *ctx.utp.borrow_mut() = Some(host);
    }
    if let Some(d) = ctx.dht() {
        d.set_port(bound.port);
    }
    // LSD: multicast membership is per interface address.
    if let Some(old) = ctx.lsd.borrow_mut().take() {
        old.retire();
    }
    if ctx.lsd_on.get()
        && let Some(l) = lsd::Lsd::open(bound.v4, bound.v6, (ctx.rng.next_u64() >> 33) as u32)
    {
        l.spawn(ctx.clone());
        *ctx.lsd.borrow_mut() = Some(l);
    }
    // External-address votes were about the old sockets.
    let now = Instant::now();
    *ctx.external.borrow_mut() = [
        super::external_ip::IpVoter::new(now),
        super::external_ip::IpVoter::new(now),
    ];
    // Peers of a family we no longer listen on.
    let families = ctx.families();
    for t in ctx.torrents.borrow().values() {
        let t = t.borrow();
        for p in t.peers.values() {
            if !families.allows(p.addr.ip()) {
                p.close("listen family removed");
            }
        }
    }
    tracing::info!(
        port = bound.port,
        v4 = ?bound.v4,
        v6 = ?bound.v6,
        "listen sockets replaced"
    );
    restart_announces(ctx, &running);
    Ok(bound.port)
}

/// End the current accept loops and wait for their listeners to close (a
/// new generation flag is installed for the loops that follow).
async fn retire_listeners(ctx: &Rc<Ctx>) {
    let old = std::mem::replace(&mut *ctx.listen_gen.borrow_mut(), Flag::new());
    old.set();
    for _ in 0..500 {
        if ctx.accept_loops.get() == 0 {
            break;
        }
        uring::sleep(Duration::from_millis(10)).await;
    }
}

/// `Session::set_dht`: start a node over the listen port's UDP sockets
/// (restoring the state of a node switched off earlier in the session, or
/// the builder's saved state), or stop the running one and keep its state.
pub fn set_dht(ctx: &Rc<Ctx>, on: bool) -> Result<(), Error> {
    if on {
        if ctx.dht().is_some() {
            return Ok(());
        }
        let v4 = ctx.udp.supports(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let v6 = ctx.udp.supports(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        if !v4 && !v6 {
            return Err(Error::Unavailable(
                "no UDP listen socket for the DHT".into(),
            ));
        }
        let saved = ctx
            .dht_saved
            .borrow_mut()
            .take()
            .or_else(|| ctx.cfg.dht_state.clone());
        let d = Rc::new(super::dht::Dht::new(
            &ctx.profile(),
            ctx.cfg.dht_read_only,
            ctx.cfg.dht_bootstrap_nodes.as_deref(),
            v4,
            v6,
            ctx.listen_port(),
            saved.as_deref(),
            &ctx.rng,
            Instant::now(),
        ));
        *ctx.dht.borrow_mut() = Some(d.clone());
        let ctx2 = ctx.clone();
        let d2 = d.clone();
        uring::spawn(async move {
            d2.start(&ctx2).await;
        });
        for t in ctx.torrents.borrow().values() {
            let t = t.borrow();
            if t.tasks_running && !t.private {
                d.announce_soon(t.id);
            }
        }
    } else if let Some(d) = ctx.dht.borrow_mut().take() {
        *ctx.dht_saved.borrow_mut() = Some(d.state());
    }
    Ok(())
}

/// `Session::set_profile`: `stopped` under the old identity, then the new
/// profile for every connection made from now on, fresh announce ids and
/// keys for every torrent (their lifetime is the profile's), the DHT node
/// restarted with its tables (its version tag is the profile's), `started`
/// under the new identity. Connections already handshaked keep the
/// identity they were made with.
pub async fn set_profile(ctx: &Rc<Ctx>, profile: profile::Profile) -> Result<(), Error> {
    let running = announce_stopped_all(ctx).await;
    {
        let mut r = super::rng::RngRef(&ctx.rng);
        ctx.peer_id.set(profile.peer_id.generate(&mut r));
    }
    *ctx.profile.borrow_mut() = profile;
    for t in ctx.torrents.borrow().values() {
        let mut t = t.borrow_mut();
        t.peer_id = ctx.new_torrent_peer_id();
        t.announce_key = ctx.new_announce_key();
    }
    if ctx.dht().is_some() {
        set_dht(ctx, false)?;
        set_dht(ctx, true)?;
    }
    tracing::info!(
        profile = ctx.profile.borrow().name,
        "identity profile replaced"
    );
    restart_announces(ctx, &running);
    Ok(())
}
