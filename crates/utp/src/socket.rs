// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors
//
// The congestion controller, retransmission, MTU discovery, selective-ack,
// nagle and close logic in this file are ported from libtorrent's
// `utp_socket_impl` (src/utp_stream.cpp, Copyright (c) 2009-2022 Arvid
// Norberg and contributors; BSD-3-Clause). See NOTICE.

//! One uTP connection as a sans-IO state machine: datagrams and `Instant`s
//! in, datagrams and notifications out. The owner feeds every packet
//! addressed to the connection to [`Socket::incoming`], calls
//! [`Socket::tick`] at [`Socket::next_timeout`], pushes application bytes
//! with [`Socket::write`], drains received bytes with [`Socket::read`] and
//! sends whatever [`Socket::poll_outgoing`] yields.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use profile::Rng;

use crate::header::{
    EXT_CLOSE_REASON, EXT_NONE, EXT_SACK, HEADER_LEN, Header, PacketType, compare_less_wrap,
    walk_extensions,
};
use crate::history::{SlidingAverage, TimestampHistory};
use crate::packet_buffer::PacketBuffer;

const ACK_MASK: u32 = 0xffff;
/// A packet that receives more than this many duplicate acks is fast-resent.
const DUP_ACK_LIMIT: u8 = 3;

/// IPv4 header size used for MTU arithmetic.
pub const IPV4_HEADER: u16 = 20;
/// IPv6 header size used for MTU arithmetic.
pub const IPV6_HEADER: u16 = 40;
/// UDP header size.
pub const UDP_HEADER: u16 = 8;
/// The link MTU assumed for every destination.
pub const ETHERNET_MTU: u16 = 1500;
/// The MTU assumed for Teredo (2001:0::/32) destinations.
pub const TEREDO_MTU: u16 = 1280;
/// The smallest MTU any IPv4 host must accept.
pub const INET_MIN_MTU: u16 = 576;

/// Tunables (libtorrent's `utp_*` settings with their defaults).
#[derive(Clone, Debug)]
pub struct Config {
    /// LEDBAT target one-way delay in milliseconds.
    pub target_delay_ms: u32,
    /// LEDBAT gain factor (bytes per RTT at full delay headroom).
    pub gain_factor: i64,
    /// Minimum retransmission timeout in milliseconds.
    pub min_timeout_ms: u32,
    /// SYN transmissions before giving up.
    pub syn_resends: u8,
    /// FIN transmissions before giving up.
    pub fin_resends: u8,
    /// Data transmissions before giving up.
    pub num_resends: u8,
    /// Time to wait for the SYN-ACK before the first retransmit, ms.
    pub connect_timeout_ms: u32,
    /// Window multiplier on loss, percent.
    pub loss_multiplier: i64,
    /// Minimum time between two window reductions, ms.
    pub cwnd_reduce_timer_ms: u32,
    /// Receive buffer capacity (the advertised window's ceiling), bytes.
    pub receive_buffer_capacity: i32,
    /// Whether to coalesce undersized packets (nagle).
    pub nagle: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            target_delay_ms: 100,
            gain_factor: 3000,
            min_timeout_ms: 500,
            syn_resends: 2,
            fin_resends: 2,
            num_resends: 3,
            connect_timeout_ms: 3000,
            loss_multiplier: 50,
            cwnd_reduce_timer_ms: 100,
            receive_buffer_capacity: 1024 * 1024,
            nagle: true,
        }
    }
}

/// The microsecond clock stamped into headers: `offset_us` plus the time
/// since `epoch` (libtorrent uses the steady clock's raw value; the owner
/// picks an offset so ours looks the same).
#[derive(Clone, Copy, Debug)]
pub struct Clock {
    epoch: Instant,
    offset_us: u64,
}

impl Clock {
    /// A clock reading `offset_us` at `epoch`.
    pub fn new(epoch: Instant, offset_us: u64) -> Clock {
        Clock { epoch, offset_us }
    }

    /// The header timestamp for `now` (wrapping 32-bit microseconds).
    pub fn micros(&self, now: Instant) -> u32 {
        let us = self.offset_us
            + u64::try_from(now.saturating_duration_since(self.epoch).as_micros())
                .unwrap_or(u64::MAX);
        us as u32
    }
}

/// Why a connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Retransmissions exhausted.
    #[error("connection timed out")]
    TimedOut,
    /// The peer sent ST_RESET.
    #[error("connection reset")]
    Reset,
    /// Torn down locally.
    #[error("connection aborted")]
    Aborted,
    /// Both directions closed cleanly.
    #[error("end of stream")]
    Eof,
}

/// Connection state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum State {
    /// Created for an incoming SYN that has not been processed yet.
    None,
    /// SYN sent, waiting for the ack.
    SynSent,
    /// Established.
    Connected,
    /// Our FIN is out.
    FinSent,
    /// Dead; the owner has been told.
    Closed,
}

/// Things the owner should look at after feeding packets or ticking.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Notify(u8);

impl Notify {
    /// The connection is established.
    pub const CONNECTED: Notify = Notify(1);
    /// Bytes (or end of stream) are readable.
    pub const READABLE: Notify = Notify(2);
    /// Write-buffer space freed up.
    pub const WRITABLE: Notify = Notify(4);
    /// The connection ended (see [`Socket::error`]).
    pub const CLOSED: Notify = Notify(8);

    /// Whether `other`'s bits are all set.
    pub fn contains(self, other: Notify) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether no bit is set.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    fn insert(&mut self, other: Notify) {
        self.0 |= other.0;
    }
}

/// A datagram to send to the connection's remote address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    /// The packet bytes.
    pub data: Vec<u8>,
    /// Whether this is a path-MTU probe (send with DF where possible).
    pub mtu_probe: bool,
}

/// Counters.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    /// Packets received (valid ones).
    pub in_packets: u32,
    /// Packets sent, including retransmissions.
    pub out_packets: u32,
    /// Retransmissions.
    pub resends: u32,
    /// Fast retransmissions.
    pub fast_resends: u32,
    /// Retransmission timeouts.
    pub timeouts: u32,
    /// Our latest one-way delay estimate (microseconds).
    pub send_delay_us: u32,
    /// The peer's latest one-way delay estimate (microseconds).
    pub recv_delay_us: u32,
    /// Payload bytes copied in user space by this socket: datagram to
    /// receive queue (one copy per received byte), write queue to packet and
    /// packet to outgoing queue (two per sent byte, the second because a
    /// packet stays in the send window for retransmission). Gated in the
    /// session's copy-budget tests.
    pub copied_bytes: u64,
}

/// A packet in the send window.
struct Packet {
    buf: Vec<u8>,
    /// Bytes the buffer may grow to (nagle packets fill up to the MTU).
    allocated: u16,
    header_size: u16,
    num_transmissions: u8,
    mtu_probe: bool,
    need_resend: bool,
    send_time: Instant,
}

impl Packet {
    fn size(&self) -> u16 {
        self.buf.len() as u16
    }

    fn payload(&self) -> i32 {
        i32::from(self.size()) - i32::from(self.header_size)
    }

    fn header(&self) -> Header {
        Header::parse(&self.buf).unwrap_or_default()
    }
}

const PKT_ACK: u8 = 1;
const PKT_FIN: u8 = 2;

/// One uTP connection.
pub struct Socket {
    cfg: Config,
    clock: Clock,
    remote: SocketAddr,
    send_id: u16,
    recv_id: u16,
    state: State,
    error: Option<Error>,

    // Application buffers.
    write_buffer: VecDeque<Vec<u8>>,
    /// Bytes of `write_buffer.front()` already consumed.
    write_head: usize,
    write_buffer_size: i32,
    receive_buffer: VecDeque<Vec<u8>>,
    receive_buffer_size: i32,

    nagle_packet: Option<Packet>,
    inbuf: PacketBuffer<Vec<u8>>,
    outbuf: PacketBuffer<Packet>,
    needs_resend: Vec<u16>,

    timeout: Instant,
    last_history_step: Instant,
    next_loss: Option<Instant>,

    cwnd: i64,
    delay_hist: TimestampHistory,
    their_delay_hist: TimestampHistory,
    ssthres: i32,
    buffered_incoming_bytes: i32,
    reply_micro: u32,
    adv_wnd: u32,
    bytes_in_flight: i32,
    delay_sample_hist: [u32; 3],
    delay_sample_idx: usize,
    rtt: SlidingAverage<16>,
    close_reason: u16,
    incoming_close_reason: Option<u16>,

    ack_nr: u16,
    seq_nr: u16,
    acked_seq_nr: u16,
    fast_resend_seq_nr: u16,
    nagle_seq_nr: u16,
    in_eof_seq_nr: u16,
    loss_seq_nr: u16,
    mtu: u16,
    mtu_floor: u16,
    mtu_ceiling: u16,
    mtu_seq: u16,
    duplicate_acks: u8,
    num_timeouts: u8,

    in_eof: bool,
    out_eof: bool,
    /// Whether the receive queue was empty when the current receive round
    /// began (see [`Socket::end_round`]).
    round_start_empty: bool,
    attached: bool,
    slow_start: bool,
    cwnd_full: bool,
    deferred_ack: bool,
    confirmed: bool,

    outgoing: VecDeque<Outgoing>,
    notify: Notify,
    stats: Stats,
    /// Set when the connection died on an oversized packet: the owner should
    /// cap the MTU for future connections (libtorrent's `restrict_mtu`).
    restrict_mtu_hint: Option<u16>,
}

impl Socket {
    fn new(
        cfg: Config,
        clock: Clock,
        remote: SocketAddr,
        send_id: u16,
        recv_id: u16,
        link_mtu: u16,
        now: Instant,
    ) -> Socket {
        let mut s = Socket {
            timeout: now + Duration::from_millis(u64::from(cfg.connect_timeout_ms)),
            cfg,
            clock,
            remote,
            send_id,
            recv_id,
            state: State::None,
            error: None,
            write_buffer: VecDeque::new(),
            write_head: 0,
            write_buffer_size: 0,
            receive_buffer: VecDeque::new(),
            receive_buffer_size: 0,
            nagle_packet: None,
            inbuf: PacketBuffer::default(),
            outbuf: PacketBuffer::default(),
            needs_resend: Vec::new(),
            last_history_step: now,
            next_loss: None,
            cwnd: i64::from(ETHERNET_MTU) << 16,
            delay_hist: TimestampHistory::default(),
            their_delay_hist: TimestampHistory::default(),
            ssthres: 0,
            buffered_incoming_bytes: 0,
            reply_micro: 0,
            adv_wnd: u32::from(ETHERNET_MTU),
            bytes_in_flight: 0,
            delay_sample_hist: [u32::MAX; 3],
            delay_sample_idx: 0,
            rtt: SlidingAverage::default(),
            close_reason: 0,
            incoming_close_reason: None,
            ack_nr: 0,
            seq_nr: 0,
            acked_seq_nr: 0,
            fast_resend_seq_nr: 0,
            nagle_seq_nr: 0,
            in_eof_seq_nr: 0,
            loss_seq_nr: 0,
            mtu: ETHERNET_MTU - IPV4_HEADER - UDP_HEADER - 8 - 24 - 36,
            mtu_floor: INET_MIN_MTU - IPV4_HEADER - UDP_HEADER,
            mtu_ceiling: ETHERNET_MTU - IPV4_HEADER - UDP_HEADER,
            mtu_seq: 0,
            duplicate_acks: 0,
            num_timeouts: 0,
            in_eof: false,
            out_eof: false,
            round_start_empty: true,
            attached: true,
            slow_start: true,
            cwnd_full: false,
            deferred_ack: false,
            confirmed: false,
            outgoing: VecDeque::new(),
            notify: Notify::default(),
            stats: Stats::default(),
            restrict_mtu_hint: None,
        };
        s.init_mtu(link_mtu);
        s
    }

    /// The UDP payload MTU towards `addr` over a 1500-byte link (1280 for
    /// Teredo), capped at `restrict` (see [`Socket::take_restrict_mtu_hint`]).
    pub fn mtu_for_dest(addr: SocketAddr, restrict: u16) -> u16 {
        let is_teredo = match addr {
            SocketAddr::V6(a) => {
                let s = a.ip().segments();
                s[0] == 0x2001 && s[1] == 0
            }
            SocketAddr::V4(_) => false,
        };
        let mut mtu = if is_teredo { TEREDO_MTU } else { ETHERNET_MTU };
        mtu -= UDP_HEADER;
        mtu -= if addr.is_ipv4() {
            IPV4_HEADER
        } else {
            IPV6_HEADER
        };
        mtu.min(restrict)
    }

    /// Open a connection to `remote`: the SYN is queued right away.
    /// `send_id` is random; `recv_id = send_id - 1` (libtorrent's rule).
    pub fn connect(
        cfg: Config,
        clock: Clock,
        remote: SocketAddr,
        send_id: u16,
        link_mtu: u16,
        now: Instant,
        rng: &mut dyn Rng,
    ) -> Socket {
        let recv_id = send_id.wrapping_sub(1);
        let mut s = Socket::new(cfg, clock, remote, send_id, recv_id, link_mtu, now);
        s.send_syn(now, rng);
        s
    }

    /// A connection for an incoming SYN carrying connection id `id`
    /// (`send_id = id`, `recv_id = id + 1`). Feed the SYN to
    /// [`Socket::incoming`] next; it returns `false` if the SYN is bad.
    pub fn accept(
        cfg: Config,
        clock: Clock,
        remote: SocketAddr,
        id: u16,
        link_mtu: u16,
        now: Instant,
    ) -> Socket {
        Socket::new(cfg, clock, remote, id, id.wrapping_add(1), link_mtu, now)
    }

    /// The remote address.
    pub fn remote(&self) -> SocketAddr {
        self.remote
    }

    /// The id we put in outgoing headers.
    pub fn send_id(&self) -> u16 {
        self.send_id
    }

    /// The id incoming packets carry.
    pub fn recv_id(&self) -> u16 {
        self.recv_id
    }

    /// Whether a packet from `ep` with connection id `id` belongs here.
    pub fn matches(&self, ep: SocketAddr, id: u16) -> bool {
        self.recv_id == id && self.remote == ep
    }

    /// Current state.
    pub fn state(&self) -> State {
        self.state
    }

    /// The error that ended the connection, once closed.
    pub fn error(&self) -> Option<Error> {
        self.error
    }

    /// Counters.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Bytes queued by [`Socket::write`] and not yet packetised.
    pub fn write_buffer_size(&self) -> usize {
        usize::try_from(self.write_buffer_size).unwrap_or(0)
    }

    /// Bytes readable right now.
    pub fn receive_buffer_size(&self) -> usize {
        usize::try_from(self.receive_buffer_size).unwrap_or(0)
    }

    /// Bytes sent and not yet acknowledged.
    pub fn bytes_in_flight(&self) -> usize {
        usize::try_from(self.bytes_in_flight).unwrap_or(0)
    }

    /// Whether everything the peer sent has been read and it closed its side.
    pub fn at_eof(&self) -> bool {
        self.receive_buffer.is_empty() && self.in_eof && self.in_eof_seq_nr == self.ack_nr
    }

    /// The peer's close reason, if it sent one (libtorrent extension 3).
    pub fn incoming_close_reason(&self) -> Option<u16> {
        self.incoming_close_reason
    }

    /// The current path MTU estimate (UDP payload bytes).
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Congestion window in bytes.
    pub fn cwnd(&self) -> usize {
        usize::try_from(self.cwnd >> 16).unwrap_or(0)
    }

    /// When [`Socket::tick`] must be called next.
    pub fn next_timeout(&self) -> Instant {
        self.timeout
    }

    /// Whether the owner may free this socket: it is dead (or never
    /// started) and detached.
    pub fn should_delete(&self) -> bool {
        (self.state == State::Closed || self.state == State::None) && !self.attached
    }

    /// Whether an ack is waiting for the end of the receive round.
    pub fn has_deferred_ack(&self) -> bool {
        self.deferred_ack
    }

    /// Set the close reason sent with our FIN (libtorrent's codes).
    pub fn set_close_reason(&mut self, code: u16) {
        self.close_reason = code;
    }

    /// Take the pending notifications.
    pub fn take_notify(&mut self) -> Notify {
        std::mem::take(&mut self.notify)
    }

    /// Take the MTU restriction hint, if a connection died on a packet
    /// larger than the floor.
    pub fn take_restrict_mtu_hint(&mut self) -> Option<u16> {
        self.restrict_mtu_hint.take()
    }

    /// The next datagram to send, if any.
    pub fn poll_outgoing(&mut self) -> Option<Outgoing> {
        self.outgoing.pop_front()
    }

    /// Queue `data` for sending and packetise what the window allows.
    pub fn write(&mut self, data: Vec<u8>, now: Instant) {
        if data.is_empty() || self.out_eof || self.state == State::Closed {
            return;
        }
        self.write_buffer_size += i32::try_from(data.len()).unwrap_or(i32::MAX);
        self.write_buffer.push_back(data);
        if self.state == State::Connected {
            while self.send_pkt(0, now) {}
        }
    }

    /// Try to send more of the write buffer (after the owner drained
    /// received data, or on any wakeup).
    pub fn flush(&mut self, now: Instant) {
        if self.state == State::Connected {
            while self.send_pkt(0, now) {}
        }
    }

    /// The next received chunk, if any.
    pub fn read(&mut self) -> Option<Vec<u8>> {
        let chunk = self.receive_buffer.pop_front()?;
        self.receive_buffer_size -= i32::try_from(chunk.len()).unwrap_or(0);
        Some(chunk)
    }

    /// Put bytes back at the front of the receive queue (a partial read).
    pub fn unread(&mut self, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        self.receive_buffer_size += i32::try_from(data.len()).unwrap_or(0);
        self.receive_buffer.push_front(data);
    }

    /// Close our side gracefully: the write buffer is flushed, then a FIN
    /// goes out.
    pub fn close(&mut self, now: Instant) {
        self.out_eof = true;
        if self.nagle_packet.is_none()
            && self.write_buffer_size == 0
            && self.state == State::Connected
            && self.outbuf.at(self.seq_nr).is_none()
        {
            self.send_fin(now);
        } else if self.state == State::Connected && self.bytes_in_flight == 0 {
            // Nothing in flight means no ack will come to drive the flush
            // (libtorrent waits for its timeout tick here); push the rest
            // now, the FIN follows once the write buffer is empty.
            while self.send_pkt(0, now) {}
        }
    }

    /// The owner is done with the socket: close it and let it finish the
    /// FIN exchange on its own; it is freed once [`Socket::should_delete`].
    pub fn detach(&mut self, now: Instant) {
        if self.attached {
            self.close(now);
            self.attached = false;
            if self.state == State::None || self.state == State::SynSent {
                self.error = Some(Error::Aborted);
                self.state = State::Closed;
            }
        }
    }

    /// Abort without a FIN (the owner is shutting down).
    pub fn abort(&mut self) {
        self.error = Some(Error::Aborted);
        self.set_closed();
    }

    /// The owner's receive round is over. libtorrent hands data that arrived
    /// in the same round as the FIN to the application together with the
    /// end-of-stream error, and the peer connection then ignores the data;
    /// so payload received in the round that completes the stream, when
    /// nothing was queued before it, is discarded here too (a peer's last
    /// message before closing is never acted upon by the oracle either).
    pub fn end_round(&mut self) {
        self.round_start_empty = self.receive_buffer.is_empty();
    }

    /// Send the deferred ack (the owner's receive round is over).
    pub fn send_deferred_ack(&mut self, now: Instant) {
        if !self.deferred_ack {
            return;
        }
        self.deferred_ack = false;
        self.send_pkt(PKT_ACK, now);
    }

    /// A probe send was rejected by the kernel with `EMSGSIZE`: the path
    /// MTU is below the probe size.
    pub fn probe_rejected(&mut self, size: u16, now: Instant) {
        if self.mtu_seq == 0 {
            return;
        }
        self.mtu_ceiling = size.saturating_sub(1);
        self.update_mtu_limits();
        let seq = self.mtu_seq;
        self.mtu_seq = 0;
        if let Some(p) = self.outbuf.at_mut(seq) {
            p.mtu_probe = false;
        }
        // resend the packet immediately without it being an MTU probe
        if let Some(p) = self.outbuf.at_mut(seq) {
            p.need_resend = true;
            self.bytes_in_flight -= p.payload();
        }
        self.needs_resend.push(seq);
        self.resend_packet(seq, false, now);
    }

    // ---- internals -------------------------------------------------------

    fn set_closed(&mut self) {
        if self.state != State::Closed {
            self.state = State::Closed;
            self.notify.insert(Notify::CLOSED);
            self.notify.insert(Notify::READABLE);
            self.notify.insert(Notify::WRITABLE);
        }
    }

    fn set_error(&mut self, e: Error) {
        if self.error.is_none() {
            self.error = Some(e);
        }
        self.set_closed();
    }

    fn emit(&mut self, data: Vec<u8>, mtu_probe: bool) {
        self.outgoing.push_back(Outgoing { data, mtu_probe });
    }

    /// [`emit`] of a copy of a packet that stays in the send window.
    ///
    /// [`emit`]: Socket::emit
    fn emit_copy(&mut self, buf: &[u8], mtu_probe: bool) {
        self.stats.copied_bytes += buf.len() as u64;
        self.emit(buf.to_vec(), mtu_probe);
    }

    fn wnd_size(&self) -> u32 {
        u32::try_from(
            self.cfg.receive_buffer_capacity
                - self.buffered_incoming_bytes
                - self.receive_buffer_size,
        )
        .unwrap_or(0)
    }

    fn init_mtu(&mut self, mtu: u16) {
        // set the ceiling to what we found out from the interface
        self.mtu_ceiling = mtu;
        // start in the middle of the PMTU search space
        self.mtu = (u32::from(self.mtu_ceiling) + u32::from(self.mtu_floor)).div_euclid(2) as u16;
        if self.mtu > self.mtu_ceiling {
            self.mtu = self.mtu_ceiling;
        }
        if self.mtu_floor > mtu {
            self.mtu_floor = mtu;
        }
        // if the window size is smaller than one packet size, set it to one
        if (self.cwnd >> 16) < i64::from(self.mtu) {
            self.cwnd = i64::from(self.mtu) << 16;
        }
    }

    fn update_mtu_limits(&mut self) {
        if self.mtu_floor > self.mtu_ceiling {
            // this is the case where we drop an MTU probe once we're in
            // steady state. Assume the probe was lost by chance, and don't
            // decrement the ceiling. We're still restarting the Path MTU
            // discovery, so if the MTU did in fact change, we'll be notified
            // again, when not in steady state.
            self.mtu_ceiling = self.mtu_floor;
            // the path MTU may have changed. Perform another search; don't
            // start all the way from start, just half way down.
            self.mtu_floor = ((INET_MIN_MTU - IPV4_HEADER - UDP_HEADER) + self.mtu_ceiling) / 2;
        }
        self.mtu = (u32::from(self.mtu_floor) + u32::from(self.mtu_ceiling)).div_euclid(2) as u16;
        if (self.cwnd >> 16) < i64::from(self.mtu) {
            self.cwnd = i64::from(self.mtu) << 16;
        }
        // clear the mtu probe sequence number since it was either dropped or
        // acked
        self.mtu_seq = 0;
    }

    fn send_syn(&mut self, now: Instant, rng: &mut dyn Rng) {
        self.seq_nr = rng.next_u32() as u16;
        self.acked_seq_nr = self.seq_nr.wrapping_sub(1);
        self.loss_seq_nr = self.acked_seq_nr;
        self.ack_nr = 0;
        self.fast_resend_seq_nr = self.seq_nr;

        let h = Header {
            ty: PacketType::Syn,
            extension: EXT_NONE,
            // using recv_id here is intentional! This is an odd thing in
            // uTP. The syn packet is sent with the connection ID that it
            // expects to receive the syn ack on. All subsequent connection
            // IDs will be this plus one.
            connection_id: self.recv_id,
            timestamp_us: self.clock.micros(now),
            timestamp_diff_us: self.reply_micro,
            wnd_size: 0,
            seq_nr: self.seq_nr,
            ack_nr: 0,
        };
        let mut buf = vec![0u8; HEADER_LEN];
        h.write(&mut buf);
        let p = Packet {
            buf: buf.clone(),
            allocated: HEADER_LEN as u16,
            header_size: HEADER_LEN as u16,
            num_transmissions: 1,
            mtu_probe: false,
            need_resend: false,
            send_time: now,
        };
        self.emit(buf, false);
        self.stats.out_packets += 1;
        self.outbuf.insert(self.seq_nr, p);
        self.seq_nr = self.seq_nr.wrapping_add(1);
        self.state = State::SynSent;
    }

    fn send_fin(&mut self, now: Instant) {
        self.send_pkt(PKT_FIN, now);
        // unless there was an error, we're now in FIN-SENT state
        if self.error.is_none() {
            if self.state != State::Closed {
                self.state = State::FinSent;
            }
        } else {
            self.set_closed();
        }
    }

    fn send_reset(&mut self, ack_nr: u16, now: Instant, rng: &mut dyn Rng) {
        let h = Header {
            ty: PacketType::Reset,
            extension: EXT_NONE,
            connection_id: self.send_id,
            timestamp_us: self.clock.micros(now),
            timestamp_diff_us: self.reply_micro,
            wnd_size: 0,
            seq_nr: rng.next_u32() as u16,
            ack_nr,
        };
        let mut buf = vec![0u8; HEADER_LEN];
        h.write(&mut buf);
        self.emit(buf, false);
    }

    fn defer_ack(&mut self) {
        self.deferred_ack = true;
    }

    /// Copy `size` bytes from the write buffer onto the end of `dst`.
    fn write_payload(&mut self, dst: &mut Vec<u8>, mut size: i32) {
        while size > 0 {
            let Some(front) = self.write_buffer.front() else {
                break;
            };
            let avail = front.len() - self.write_head;
            let to_copy = usize::try_from(size).unwrap_or(0).min(avail);
            dst.extend_from_slice(&front[self.write_head..self.write_head + to_copy]);
            self.stats.copied_bytes += to_copy as u64;
            self.write_head += to_copy;
            self.write_buffer_size -= to_copy as i32;
            size -= to_copy as i32;
            if self.write_head == front.len() {
                self.write_buffer.pop_front();
                self.write_head = 0;
            }
            self.notify.insert(Notify::WRITABLE);
        }
    }

    /// The selective-ack bitmask for `size` bytes, starting at `ack_nr + 2`.
    fn write_sack(&self, out: &mut [u8]) {
        let mut ack_nr = u32::from(self.ack_nr).wrapping_add(2) & ACK_MASK;
        for b in out.iter_mut() {
            *b = 0;
            let mut mask = 1u8;
            for _ in 0..8 {
                if self.inbuf.at(ack_nr as u16).is_some() {
                    *b |= mask;
                }
                mask = mask.wrapping_shl(1);
                ack_nr = (ack_nr + 1) & ACK_MASK;
            }
        }
    }

    fn remove_sack_header(p: &mut Packet) {
        let next = p.buf[HEADER_LEN];
        let sack_size = usize::from(p.buf[HEADER_LEN + 1]);
        p.buf[1] = next;
        p.buf.drain(HEADER_LEN..HEADER_LEN + 2 + sack_size);
        p.header_size -= (sack_size + 2) as u16;
    }

    fn insert_packet(&mut self, p: Packet) {
        let seq = self.seq_nr;
        if let Some(old) = self.outbuf.insert(seq, p) {
            if old.need_resend {
                self.needs_resend.retain(|&s| s != seq);
            } else {
                self.bytes_in_flight -= old.payload();
            }
        }
    }

    /// Send a packet, pulling data from the write buffer. `PKT_ACK` forces a
    /// packet even without payload; `PKT_FIN` makes it a FIN. Returns true
    /// when there is room for more payload in the windows.
    fn send_pkt(&mut self, flags: u8, now: Instant) -> bool {
        // m_out_eof means we're trying to close the write side of this
        // socket, we need to flush all payload before we can send the FIN
        // packet, so don't store any payload in the nagle packet
        let force = flags & PKT_ACK != 0 || flags & PKT_FIN != 0 || self.out_eof;
        // when we want to close the outgoing stream, we need to send the
        // remaining nagle packet even though it won't fill a packet.
        let force_flush_nagle = self.out_eof && self.write_buffer_size > 0;

        // first see if we need to resend any packets
        while let Some(&seq) = self.needs_resend.first() {
            if self.outbuf.at(seq).is_none() {
                self.needs_resend.remove(0);
                continue;
            }
            if !self.resend_packet(seq, false, now) {
                // we couldn't resend the packet. It probably doesn't fit in
                // our cwnd. If force is set, we need to continue to send our
                // packet anyway, if we don't have force set, we might as
                // well return
                if !force {
                    return false;
                }
                if self.state == State::Closed {
                    return false;
                }
                break;
            }
            // don't fast-resend this packet
            if self.fast_resend_seq_nr == seq {
                self.fast_resend_seq_nr = self.fast_resend_seq_nr.wrapping_add(1);
            }
            self.needs_resend.retain(|&s| s != seq);
        }

        // MTU DISCOVERY: under these conditions, the next packet we send
        // should be an MTU probe. MTU probes get to use the mid-point packet
        // size, whereas other packets use a conservative packet size of the
        // largest known to work. The reason for the cwnd condition is to
        // make sure the probe is surrounded by non-probes, to be able to
        // distinguish a loss of the probe vs. just loss in general.
        let mtu_probe = self.mtu_seq == 0
            && self.seq_nr != 0
            && (self.cwnd >> 16) > i64::from(self.mtu_floor) * 3;
        // for non MTU-probes, use the conservative packet size
        let effective_mtu = i32::from(if mtu_probe { self.mtu } else { self.mtu_floor });

        let mut close_reason = u32::from(self.close_reason);

        let mut sack: i32 = 0;
        if !self.inbuf.is_empty() {
            let max_sack_size =
                effective_mtu - HEADER_LEN as i32 - 2 - if close_reason != 0 { 6 } else { 0 };
            // the SACK bitfield should ideally fit all the pieces we have
            // successfully received
            sack = self.inbuf.span().div_ceil(8) as i32;
            if sack > max_sack_size {
                sack = max_sack_size;
            }
        }

        let header_size = HEADER_LEN as i32
            + if sack != 0 { sack + 2 } else { 0 }
            + if close_reason != 0 { 6 } else { 0 };

        let nagle_size = self.nagle_packet.as_ref().map_or(0, Packet::payload);
        let mut payload_size =
            (self.write_buffer_size + nagle_size).min(effective_mtu - header_size);
        if payload_size < 0 {
            payload_size = 0;
        }
        // we cannot include any payload in FIN packets
        if flags & PKT_FIN != 0 {
            payload_size = 0;
        }

        // if we have one MSS worth of data, make sure it fits in our
        // congestion window and the advertised receive window from the other
        // end.
        let window = i64::min(self.cwnd >> 16, i64::from(self.adv_wnd));
        if i64::from(self.bytes_in_flight) + i64::from(payload_size) > window {
            // we can't fit a full packet of payload in the cwnd, but if
            // we're sending an ACK, we can send a packet without payload
            if flags & PKT_ACK != 0 {
                payload_size = 0;
            }
            // we're constrained by the window size
            self.cwnd_full = true;
            if !force {
                return false;
            }
        }

        // if we don't have any data to send, or can't send any data and we
        // don't have any data to force, don't send a packet
        if payload_size == 0 && !force {
            return false;
        }

        // payload size being zero means we're just sending an ack. For
        // efficiency, pick up the nagle packet if there's room. Note that if
        // there is a nagle packet, payload_size will include its size, so we
        // won't take the first branch here
        let mut p = if self.nagle_packet.is_none() || (payload_size == 0 && force && self.cwnd_full)
        {
            let mut buf = vec![0u8; header_size as usize];
            let h = Header {
                ty: if payload_size != 0 {
                    PacketType::Data
                } else {
                    PacketType::State
                },
                extension: if sack != 0 {
                    EXT_SACK
                } else if close_reason != 0 {
                    EXT_CLOSE_REASON
                } else {
                    EXT_NONE
                },
                connection_id: self.send_id,
                // seq_nr is ignored for ST_STATE packets, so it doesn't
                // matter that we say this is a sequence number we haven't
                // actually sent yet
                seq_nr: self.seq_nr,
                ..Header::default()
            };
            h.write(&mut buf);
            self.write_payload(&mut buf, payload_size);
            Packet {
                buf,
                allocated: effective_mtu.max(header_size) as u16,
                header_size: header_size as u16,
                num_transmissions: 0,
                mtu_probe: false,
                need_resend: false,
                send_time: now,
            }
        } else {
            // pick up the nagle packet and keep adding bytes to it
            let Some(mut p) = self.nagle_packet.take() else {
                return false;
            };
            // if the packet has a selective ack header, we'll need to update
            // it
            if p.buf[1] == EXT_SACK {
                sack = i32::from(p.buf[HEADER_LEN + 1]);
                // if we no longer have any out-of-order packets waiting to be
                // delivered, there's no selective ack to be sent.
                if self.inbuf.is_empty() {
                    // we need to remove the sack header
                    Self::remove_sack_header(&mut p);
                    sack = 0;
                }
            } else {
                sack = 0;
            }
            // we should not add or update a close reason extension header on
            // a nagle packet. It's a bit tricky to get all the cases right.
            close_reason = 0;

            let size_left = i32::from(p.allocated)
                .saturating_sub(i32::from(p.size()))
                .min(self.write_buffer_size)
                .min(effective_mtu - i32::from(p.size()));
            if size_left > 0 {
                self.write_payload(&mut p.buf, size_left);
            }

            // did we fill up the whole mtu? if we didn't, we may still send
            // it if there's no undersized packet currently in flight
            if self.bytes_in_flight > 0
                && i32::from(p.size()) < i32::from(p.allocated).min(effective_mtu)
                && !force
                && self.cfg.nagle
                && compare_less_wrap(
                    u32::from(self.acked_seq_nr),
                    u32::from(self.nagle_seq_nr),
                    ACK_MASK,
                )
            {
                // the packet is still not a full MSS, so put it back into
                // the nagle packet
                self.nagle_packet = Some(p);
                return false;
            }
            p
        };

        if sack != 0 {
            let at = HEADER_LEN;
            p.buf[at] = if close_reason != 0 {
                EXT_CLOSE_REASON
            } else {
                EXT_NONE
            };
            p.buf[at + 1] = sack as u8; // bytes for SACK bitfield
            let mut bits = vec![0u8; sack as usize];
            self.write_sack(&mut bits);
            p.buf[at + 2..at + 2 + sack as usize].copy_from_slice(&bits);
        }
        if close_reason != 0 {
            let at = HEADER_LEN + if sack != 0 { sack as usize + 2 } else { 0 };
            p.buf[at] = EXT_NONE;
            p.buf[at + 1] = 4;
            p.buf[at + 2..at + 6].copy_from_slice(&close_reason.to_be_bytes());
        }

        if self.bytes_in_flight > 0
            && i32::from(p.size()) < i32::from(p.allocated).min(effective_mtu)
            && !force_flush_nagle
            && !force
            && self.cfg.nagle
            && compare_less_wrap(
                u32::from(self.acked_seq_nr),
                u32::from(self.nagle_seq_nr),
                ACK_MASK,
            )
        {
            // this is nagle. If we don't have a full packet worth of payload
            // to send AND we have at least one outstanding undersized
            // packet, hold off. Once the outstanding packet is acked, we'll
            // send this payload
            self.nagle_packet = Some(p);
            return false;
        }

        // for ST_STATE packets, payload size is 0. Such packets do not have
        // unique sequence numbers and should never be used as mtu probes
        if (mtu_probe || p.mtu_probe) && p.size() >= self.mtu_floor && p.payload() > 0 {
            p.mtu_probe = true;
            self.mtu_seq = self.seq_nr;
        } else {
            p.mtu_probe = false;
        }

        let mut h = p.header();
        h.timestamp_diff_us = self.reply_micro;
        h.wnd_size = self.wnd_size();
        h.ack_nr = self.ack_nr;
        // if this is a FIN packet, override the type
        if flags & PKT_FIN != 0 {
            h.ty = PacketType::Fin;
        }
        // fill in the timestamp as late as possible
        p.send_time = now;
        h.timestamp_us = self.clock.micros(now);
        h.write(&mut p.buf);

        self.emit_copy(&p.buf, p.mtu_probe);
        self.stats.out_packets += 1;
        p.num_transmissions = p.num_transmissions.saturating_add(1);
        // Only reset the timeout for the initial packet
        if self.bytes_in_flight == 0 {
            self.timeout = now + Duration::from_millis(u64::from(self.packet_timeout()));
        }
        // Any queued up deferred ack is now redundant
        self.deferred_ack = false;

        // if we have payload, we need to save the packet until it's acked
        // and progress m_seq_nr
        if p.payload() > 0 {
            // If this packet is undersized then note the sequence number so
            // we never have more than one undersized packet in flight at once
            if i32::from(p.size()) < i32::from(p.allocated).min(effective_mtu) {
                self.nagle_seq_nr = self.seq_nr;
            }
            let new_in_flight = p.payload();
            self.insert_packet(p);
            self.seq_nr = self.seq_nr.wrapping_add(1);
            self.bytes_in_flight += new_in_flight;
        } else if flags & PKT_FIN != 0 {
            self.insert_packet(p);
        } else if self.out_eof
            && self.write_buffer_size == 0
            && self.nagle_packet.is_none()
            && self.state == State::Connected
        {
            // this is a re-entrant call, so we have to be careful only
            // making it if we're not already sending a FIN
            self.send_fin(now);
        }

        self.write_buffer_size > 0 && !self.cwnd_full
    }

    /// Retransmit the packet at `seq`. Returns false if the window does not
    /// allow it.
    fn resend_packet(&mut self, seq: u16, fast_resend: bool, now: Instant) -> bool {
        if self.error.is_some() {
            return false;
        }
        let Some(mut p) = self.outbuf.remove(seq) else {
            return true;
        };
        if self.acked_seq_nr.wrapping_add(1) == self.mtu_seq && self.mtu_seq != 0 {
            self.mtu_seq = 0;
            p.mtu_probe = false;
            // we got multiple acks for the packet before our probe, assume it
            // was dropped because it was too big
            self.mtu_ceiling = p.size().saturating_sub(1);
            self.update_mtu_limits();
        }

        // we can only resend the packet if there's enough space in our
        // congestion window. since we can't re-packetize, some packets that
        // are larger than the congestion window must be allowed through but
        // only if we don't have any outstanding bytes
        let window_size_left =
            i64::min(self.cwnd >> 16, i64::from(self.adv_wnd)) - i64::from(self.bytes_in_flight);
        if !fast_resend && i64::from(p.payload()) > window_size_left && self.bytes_in_flight > 0 {
            self.cwnd_full = true;
            self.outbuf.insert(seq, p);
            return false;
        }

        if p.need_resend {
            self.bytes_in_flight += p.payload();
        }
        self.stats.resends += 1;
        if fast_resend {
            self.stats.fast_resends += 1;
        }
        let need_resend = p.need_resend;
        p.need_resend = false;
        let mut h = p.header();
        // update packet header
        h.timestamp_diff_us = self.reply_micro;
        p.send_time = now;
        h.timestamp_us = self.clock.micros(now);
        // if the packet has a selective ack header, we'll need to update it
        if h.extension == EXT_SACK && h.ack_nr != self.ack_nr {
            let sack_size = usize::from(p.buf[HEADER_LEN + 1]);
            if !self.inbuf.is_empty() {
                let mut bits = vec![0u8; sack_size];
                self.write_sack(&mut bits);
                p.buf[HEADER_LEN + 2..HEADER_LEN + 2 + sack_size].copy_from_slice(&bits);
            } else {
                Self::remove_sack_header(&mut p);
                h.extension = p.buf[1];
            }
        }
        h.ack_nr = self.ack_nr;
        h.write(&mut p.buf);

        self.emit_copy(&p.buf, p.mtu_probe);
        if need_resend {
            self.needs_resend.retain(|&s| s != seq);
        }
        self.stats.out_packets += 1;
        p.num_transmissions = p.num_transmissions.saturating_add(1);
        self.outbuf.insert(seq, p);
        true
    }

    fn experienced_loss(&mut self, seq_nr: u32, now: Instant) {
        // since loss often comes in bursts, we only cut the window in half
        // once per RTT. This is implemented by limiting which packets can
        // cause us to cut the window size. The first packet that's lost will
        // update the limit to the last sequence number we sent. i.e. only
        // packet sent after this loss can cause another window size cut. The
        // +1 is to turn the comparison into less than or equal to. If we
        // experience loss of the same packet again, ignore it.
        if compare_less_wrap(seq_nr, u32::from(self.loss_seq_nr) + 1, ACK_MASK) {
            return;
        }
        // don't reduce cwnd more than once every 100ms
        if self.next_loss.is_some_and(|t| t >= now) {
            return;
        }
        self.next_loss =
            Some(now + Duration::from_millis(u64::from(self.cfg.cwnd_reduce_timer_ms)));
        // cut window size in 2
        self.cwnd = i64::max(
            self.cwnd * self.cfg.loss_multiplier / 100,
            i64::from(self.mtu) << 16,
        );
        self.loss_seq_nr = self.seq_nr;
        // if we happen to be in slow-start mode, we need to leave it. note
        // that we set ssthres to the window size _after_ reducing it. Next
        // slow start should end before we over shoot.
        if self.slow_start {
            self.ssthres = (self.cwnd >> 16) as i32;
            self.slow_start = false;
        }
    }

    fn maybe_inc_acked_seq_nr(&mut self) {
        let mut incremented = false;
        // don't pass m_seq_nr, since we move into sequence numbers that
        // haven't been sent yet, and aren't supposed to be in m_outbuf. once
        // we're in the fin_sent state m_acked_seq_nr can equal m_seq_nr, but
        // shouldn't reach m_seq_nr + 1
        let limit = if self.state == State::FinSent {
            self.seq_nr.wrapping_add(1)
        } else {
            self.seq_nr
        };
        while self.acked_seq_nr.wrapping_add(1) != limit
            && self.outbuf.at(self.acked_seq_nr.wrapping_add(1)).is_none()
        {
            // increment the fast resend sequence number
            if self.fast_resend_seq_nr == self.acked_seq_nr {
                self.fast_resend_seq_nr = self.fast_resend_seq_nr.wrapping_add(1);
            }
            self.acked_seq_nr = self.acked_seq_nr.wrapping_add(1);
            incremented = true;
        }
        if !incremented {
            return;
        }
        // update loss seq number if it's less than the packet that was just
        // acked. If loss seq nr is greater, it suggests that we're still in
        // a window that has experienced loss
        if compare_less_wrap(
            u32::from(self.loss_seq_nr),
            u32::from(self.acked_seq_nr),
            ACK_MASK,
        ) {
            self.loss_seq_nr = self.acked_seq_nr;
        }
        self.duplicate_acks = 0;
    }

    /// Account for an acked packet; returns its RTT in microseconds.
    fn ack_packet(&mut self, p: Packet, receive_time: Instant, seq_nr: u16) -> u32 {
        if p.need_resend {
            self.needs_resend.retain(|&s| s != seq_nr);
        } else {
            self.bytes_in_flight -= p.payload();
        }
        if seq_nr == self.mtu_seq && self.mtu_seq != 0 {
            // our mtu probe was acked!
            self.mtu_floor = self.mtu_floor.max(p.size());
            self.update_mtu_limits();
        }
        // increment the acked sequence number counter
        self.maybe_inc_acked_seq_nr();

        let rtt = if receive_time < p.send_time {
            // this means our clock is not monotonic. Just assume the RTT was
            // 100 ms
            100_000
        } else {
            u32::try_from((receive_time - p.send_time).as_micros()).unwrap_or(u32::MAX)
        };
        self.rtt.add_sample(i64::from(rtt / 1000));
        rtt
    }

    /// Store a received payload for the application.
    fn incoming_payload(&mut self, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        self.receive_buffer_size += data.len() as i32;
        self.receive_buffer.push_back(data);
        self.notify.insert(Notify::READABLE);
    }

    /// Returns `(rtt, acked_bytes)`.
    fn parse_sack(&mut self, packet_ack: u16, bits: &[u8], now: Instant) -> (u32, i32) {
        if bits.is_empty() {
            return (0, 0);
        }
        // this is the sequence number the current bit represents
        let mut ack_nr = (u32::from(packet_ack) + 2) & ACK_MASK;
        let mut resend: [u16; 5] = [0; 5];
        let mut num_to_resend = 0usize;
        let mut acked_bytes = 0i32;
        let mut min_rtt = u32::MAX;

        // this was implicitly lost
        if !compare_less_wrap(
            (u32::from(packet_ack) + 1) & ACK_MASK,
            u32::from(self.fast_resend_seq_nr),
            ACK_MASK,
        ) {
            resend[num_to_resend] = packet_ack.wrapping_add(1);
            num_to_resend += 1;
        }

        'outer: for &bitfield in bits {
            let mut mask = 1u8;
            for _ in 0..8 {
                if mask & bitfield != 0 {
                    // this bit was set, ack_nr was received
                    if let Some(p) = self.outbuf.remove(ack_nr as u16) {
                        acked_bytes += p.payload();
                        // each ACKed packet counts as a duplicate ack
                        let rtt = self.ack_packet(p, now, ack_nr as u16);
                        min_rtt = min_rtt.min(rtt);
                    } else {
                        // this packet might have been acked by a previous
                        // selective ack
                        self.maybe_inc_acked_seq_nr();
                    }
                } else if !compare_less_wrap(ack_nr, u32::from(self.fast_resend_seq_nr), ACK_MASK)
                    && num_to_resend < resend.len()
                {
                    resend[num_to_resend] = ack_nr as u16;
                    num_to_resend += 1;
                }
                mask = mask.wrapping_shl(1);
                ack_nr = (ack_nr + 1) & ACK_MASK;
                // we haven't sent packets past this point. if there are any
                // more bits set, we have to ignore them anyway
                if ack_nr as u16 == self.seq_nr {
                    break 'outer;
                }
            }
        }

        if self.outbuf.is_empty() {
            self.duplicate_acks = 0;
        }

        // now, scan the bits in reverse, and count the number of ACKed
        // packets. Only lost packets followed by 'dup_ack_limit' packets may
        // be resent. start with the sequence number represented by the last
        // bit in the SACK bitmask
        let mut last_resend = (u32::from(packet_ack) + 1 + bits.len() as u32 * 8) & ACK_MASK;
        // the number of acked packets past the fast re-send sequence number;
        // this is used to determine if we should trigger more fast re-sends
        let mut dups = 0u8;
        'rev: for &bitfield in bits.iter().rev() {
            let mut mask = 0x80u8;
            for _ in 0..8 {
                if mask & bitfield != 0 {
                    dups += 1;
                }
                if dups > DUP_ACK_LIMIT {
                    break 'rev;
                }
                last_resend = last_resend.wrapping_sub(1) & ACK_MASK;
                mask >>= 1;
            }
        }
        // we did not get enough packets acked in this message to warrant a
        // resend
        if dups <= DUP_ACK_LIMIT {
            num_to_resend = 0;
        }
        // now we need to (likely) prune the tail of the resend list, since
        // all "unacked" packets that weren't followed by an acked one, don't
        // count
        while num_to_resend > 0
            && !compare_less_wrap(u32::from(resend[num_to_resend - 1]), last_resend, ACK_MASK)
        {
            num_to_resend -= 1;
        }

        let mut cut_cwnd = true;
        // we received more than dup_ack_limit ACKs in this SACK message.
        // trigger fast re-send. This is not an equal check because 3
        // identical ACKS are only 2 duplicates
        for &pkt_seq in &resend[..num_to_resend] {
            if self.outbuf.at(pkt_seq).is_none() {
                continue;
            }
            // don't cut cwnd if the packet we lost was the MTU probe; the
            // logic to handle a lost MTU probe is in resend_packet()
            if cut_cwnd && (pkt_seq != self.mtu_seq || self.mtu_seq == 0) {
                self.experienced_loss(u32::from(pkt_seq), now);
                cut_cwnd = false;
            }
            if self.resend_packet(pkt_seq, true, now) {
                self.duplicate_acks = 0;
                self.fast_resend_seq_nr = pkt_seq.wrapping_add(1);
            }
        }
        (min_rtt, acked_bytes)
    }

    /// Deliver a data packet's payload in order (or park it in the reorder
    /// buffer). Returns true when the packet was dropped/ignored.
    fn consume_incoming_data(&mut self, h: &Header, payload: &[u8]) -> bool {
        if h.ty != PacketType::Data {
            return false;
        }
        if self.in_eof && self.ack_nr == self.in_eof_seq_nr {
            // What?! We've already received a FIN and everything up to it
            // has been acked. Ignore this packet
            return true;
        }
        let payload_size = payload.len() as i32;
        if self.receive_buffer_size
            >= self.cfg.receive_buffer_capacity - self.buffered_incoming_bytes
        {
            // the number of queued up bytes, waiting for the upper layer,
            // exceeds the advertised receive window: start ignoring more
            // data packets
            return false;
        }
        if h.seq_nr == self.ack_nr.wrapping_add(1) {
            if self.buffered_incoming_bytes + self.receive_buffer_size + payload_size
                > self.cfg.receive_buffer_capacity
            {
                return true;
            }
            // we received a packet in order
            self.stats.copied_bytes += payload.len() as u64;
            self.incoming_payload(payload.to_vec());
            self.ack_nr = self.ack_nr.wrapping_add(1);
            // If this packet was previously in the reorder buffer it would
            // have been acked when m_ack_nr-1 was acked.
            loop {
                let next_ack_nr = self.ack_nr.wrapping_add(1);
                let Some(p) = self.inbuf.remove(next_ack_nr) else {
                    break;
                };
                self.buffered_incoming_bytes -= p.len() as i32;
                self.incoming_payload(p);
                self.ack_nr = next_ack_nr;
            }
        } else {
            // this packet was received out of order. Stick it in the reorder
            // buffer until it can be delivered in order. have we already
            // received this packet and passed it on to the client?
            if !compare_less_wrap(u32::from(self.ack_nr), u32::from(h.seq_nr), ACK_MASK) {
                return true;
            }
            // do we already have this packet? If so, just ignore it
            if self.inbuf.at(h.seq_nr).is_some() {
                return true;
            }
            if self.buffered_incoming_bytes + self.receive_buffer_size + payload_size
                > self.cfg.receive_buffer_capacity
            {
                return true;
            }
            // we don't need to save the packet header, just the payload
            self.buffered_incoming_bytes += payload_size;
            self.stats.copied_bytes += payload.len() as u64;
            self.inbuf.insert(h.seq_nr, payload.to_vec());
        }
        false
    }

    /// Feed a datagram from `from`. Returns false for packets that are not
    /// for this connection (bad id, bad version).
    pub fn incoming(
        &mut self,
        from: SocketAddr,
        pkt: &[u8],
        now: Instant,
        rng: &mut dyn Rng,
    ) -> bool {
        let receive_time = now;
        let Some(h) = Header::parse(pkt) else {
            return false;
        };
        // SYN packets have special (reverse) connection ids
        if h.ty != PacketType::Syn && h.connection_id != self.recv_id {
            return false;
        }
        if self.state == State::None && h.ty == PacketType::Syn {
            self.remote = from;
        }
        if self.state != State::None && h.ty == PacketType::Syn {
            return true;
        }

        let mut step = false;
        if receive_time.saturating_duration_since(self.last_history_step) > Duration::from_secs(60)
        {
            step = true;
            self.last_history_step = receive_time;
        }

        // this is the difference between their send time and our receive
        // time; 0 means no sample yet
        let mut their_delay = 0u32;
        if h.timestamp_us != 0 {
            let timestamp = self.clock.micros(receive_time);
            self.reply_micro = timestamp.wrapping_sub(h.timestamp_us);
            let prev_base = if self.their_delay_hist.initialized() {
                self.their_delay_hist.base()
            } else {
                0
            };
            their_delay = self.their_delay_hist.add_sample(self.reply_micro, step);
            let base_change = self.their_delay_hist.base().wrapping_sub(prev_base) as i32;
            if prev_base != 0
                && base_change < 0
                && base_change > -10_000
                && self.delay_hist.initialized()
            {
                // their base delay went down. This is caused by clock drift.
                // To compensate, adjust our base delay upwards. don't adjust
                // more than 10 ms. If the change is that big, something is
                // probably wrong
                self.delay_hist.adjust_base(-base_change);
            }
        }

        let state_or_fin = h.ty == PacketType::State || h.ty == PacketType::Fin;

        // is this ACK valid? If the other end is ACKing a packet that hasn't
        // been sent yet just ignore it. A 3rd party could easily inject a
        // packet like this in a stream, don't sever it because of it. since
        // m_seq_nr is the sequence number of the next packet we'll send (and
        // m_seq_nr-1 was the last packet we sent), if the ACK we got is
        // greater than the last packet we sent something is wrong. If our
        // state is state_none, this packet must be a syn packet and the
        // ack_nr should be ignored. Note that when we send a FIN, we don't
        // increment m_seq_nr
        let cmp_seq_nr = if (self.state == State::SynSent
            || self.state == State::FinSent
            || self.state == State::Closed)
            && state_or_fin
        {
            self.seq_nr
        } else {
            self.seq_nr.wrapping_sub(1)
        };
        if (self.state != State::None || h.ty != PacketType::Syn)
            && (compare_less_wrap(u32::from(cmp_seq_nr), u32::from(h.ack_nr), ACK_MASK)
                || compare_less_wrap(
                    u32::from(h.ack_nr),
                    u32::from(self.acked_seq_nr.wrapping_sub(u16::from(DUP_ACK_LIMIT))),
                    ACK_MASK,
                ))
        {
            return true;
        }

        // if the socket is closing, always ignore any packet with a higher
        // sequence number than the FIN sequence number. ST_STATE messages
        // always include the next seqnr, so it's acceptable to receive the
        // same seq_nr as the EOF as long as it's a STATE or FIN packet
        if self.in_eof
            && compare_less_wrap(u32::from(self.in_eof_seq_nr), u32::from(h.seq_nr), ACK_MASK)
            && !(self.in_eof_seq_nr == h.seq_nr && state_or_fin)
        {
            return true;
        }

        // the number of packets that'll fit in the reorder buffer
        let max_packets_reorder =
            u32::try_from((self.cfg.receive_buffer_capacity / 1100).max(16)).unwrap_or(16);
        if self.state != State::None
            && self.state != State::SynSent
            && compare_less_wrap(
                (u32::from(self.ack_nr) + max_packets_reorder) & ACK_MASK,
                u32::from(h.seq_nr),
                ACK_MASK,
            )
        {
            // this is too far out to fit in our reorder buffer. Drop it
            return true;
        }

        if h.ty == PacketType::Reset {
            if compare_less_wrap(u32::from(cmp_seq_nr), u32::from(h.ack_nr), ACK_MASK) {
                return true;
            }
            self.set_error(Error::Reset);
            return true;
        }

        self.stats.in_packets += 1;

        // the test for INT_MAX here is a work-around for a bug in uTorrent
        // where it's sometimes sent as INT_MAX when it is in fact
        // uninitialized
        let sample = if h.timestamp_diff_us == i32::MAX as u32 {
            0
        } else {
            h.timestamp_diff_us
        };
        let mut delay = 0u32;
        if sample != 0 {
            delay = self.delay_hist.add_sample(sample, step);
            self.delay_sample_hist[self.delay_sample_idx] = delay;
            self.delay_sample_idx = (self.delay_sample_idx + 1) % self.delay_sample_hist.len();
        }

        let mut acked_bytes = 0i32;
        let prev_bytes_in_flight = self.bytes_in_flight;
        self.adv_wnd = h.wnd_size;

        // if we get an ack for the same sequence number as was last ACKed,
        // and we have outstanding packets, it counts as a duplicate ack. The
        // reason to not count ST_DATA packets as duplicate ACKs is because we
        // may be receiving a stream of those regardless of our outgoing
        // traffic, which makes their ACK number not indicative of a dropped
        // packet
        if h.ack_nr == self.acked_seq_nr && !self.outbuf.is_empty() && h.ty == PacketType::State {
            self.duplicate_acks = self.duplicate_acks.saturating_add(1);
        }

        let mut min_rtt = u32::MAX;

        // has this packet already been ACKed? if the ACK we just got is less
        // than the max ACKed sequence number, it doesn't tell us anything.
        // So, only act on it if the ACK is greater than the last acked
        // sequence number
        if self.state != State::None
            && compare_less_wrap(u32::from(self.acked_seq_nr), u32::from(h.ack_nr), ACK_MASK)
        {
            let next_ack_nr = h.ack_nr;
            let mut ack_nr = self.acked_seq_nr.wrapping_add(1);
            while ack_nr != next_ack_nr.wrapping_add(1) {
                if self.fast_resend_seq_nr == ack_nr {
                    self.fast_resend_seq_nr = self.fast_resend_seq_nr.wrapping_add(1);
                }
                if let Some(p) = self.outbuf.remove(ack_nr) {
                    acked_bytes += p.payload();
                    let rtt = self.ack_packet(p, receive_time, ack_nr);
                    min_rtt = min_rtt.min(rtt);
                }
                ack_nr = ack_nr.wrapping_add(1);
            }
            self.maybe_inc_acked_seq_nr();
            if self.outbuf.is_empty() {
                self.duplicate_acks = 0;
            }
        }

        // look for extended headers
        let mut sack_bits: Option<Vec<u8>> = None;
        let mut close_reason: Option<u16> = None;
        let Some(payload_off) = walk_extensions(&h, pkt, |ext, body| match ext {
            EXT_SACK => sack_bits = Some(body.to_vec()),
            // skip the two reserved bytes
            EXT_CLOSE_REASON if body.len() == 4 => {
                close_reason = Some(u16::from_be_bytes([body[2], body[3]]));
            }
            _ => {}
        }) else {
            // invalid packet. It says it has an extension header but the
            // packet is too short
            return true;
        };
        if let Some(bits) = sack_bits {
            let (rtt, acked) = self.parse_sack(h.ack_nr, &bits, receive_time);
            acked_bytes = acked;
            min_rtt = min_rtt.min(rtt);
        }
        if let Some(r) = close_reason {
            self.incoming_close_reason = Some(r);
        }

        // this is a valid incoming packet, update the timeout timer. do this
        // after processing sacks/acks as that can effect packet_timeout()
        self.num_timeouts = 0;
        self.timeout = receive_time + Duration::from_millis(u64::from(self.packet_timeout()));

        if self.duplicate_acks >= DUP_ACK_LIMIT
            && self.acked_seq_nr.wrapping_add(1) == self.fast_resend_seq_nr
        {
            // LOSS: resend the lost packet
            let seq = self.fast_resend_seq_nr;
            // don't fast-resend this again
            self.fast_resend_seq_nr = self.fast_resend_seq_nr.wrapping_add(1);
            if let Some(p) = self.outbuf.at(seq) {
                // don't consider a lost probe as proper loss, it doesn't
                // necessarily signal congestion
                if !p.mtu_probe {
                    self.experienced_loss(u32::from(self.fast_resend_seq_nr), receive_time);
                }
                self.resend_packet(seq, true, now);
            }
        }

        let payload = &pkt[payload_off..];
        let payload_size = payload.len();

        if h.ty == PacketType::Fin {
            // We ignore duplicate FIN packets, but we still need to ACK them.
            if h.seq_nr == self.ack_nr.wrapping_add(1) || h.seq_nr == self.ack_nr {
                // The FIN arrived in order, nothing else is in the reorder
                // buffer.
                self.ack_nr = h.seq_nr;
            }
            if !self.in_eof {
                self.in_eof = true;
                // even though invalid, tolerate FIN packets with payload
                self.in_eof_seq_nr = if payload_size > 0 {
                    h.seq_nr.wrapping_add(1)
                } else {
                    h.seq_nr
                };
            }
            self.defer_ack();
            if self.ack_nr == self.in_eof_seq_nr {
                if self.round_start_empty && !self.receive_buffer.is_empty() {
                    // Same round as the FIN with an idle reader: dropped, as
                    // libtorrent's peer connection drops it (see `end_round`).
                    self.receive_buffer.clear();
                    self.receive_buffer_size = 0;
                }
                if self.receive_buffer.is_empty() {
                    self.notify.insert(Notify::READABLE);
                }
            }
            return true;
        }

        // the send operation in parse_sack() may have set the socket to an
        // error state, in which case we shouldn't continue
        if self.state == State::Closed {
            return true;
        }

        match self.state {
            State::None => {
                if h.ty == PacketType::Syn {
                    // if we're in state_none, the only thing we accept are
                    // SYN packets.
                    self.state = State::Connected;
                    self.remote = from;
                    self.ack_nr = h.seq_nr;
                    self.seq_nr = rng.next_u32() as u16;
                    self.acked_seq_nr = self.seq_nr.wrapping_sub(1);
                    self.loss_seq_nr = self.acked_seq_nr;
                    self.fast_resend_seq_nr = self.seq_nr;
                    if self.send_id != h.connection_id {
                        return false;
                    }
                    self.notify.insert(Notify::CONNECTED);
                    self.defer_ack();
                }
            }
            State::SynSent | State::Connected => {
                if self.state == State::SynSent {
                    // just wait for an ack to our SYN, ignore everything else
                    if h.ack_nr != self.seq_nr.wrapping_sub(1) {
                        return true;
                    }
                    self.state = State::Connected;
                    // only progress our ack_nr on ST_DATA messages since our
                    // m_ack_nr is uninitialized at this point we still need
                    // to set it to something regardless
                    self.ack_nr = if h.ty == PacketType::Data {
                        h.seq_nr
                    } else {
                        h.seq_nr.wrapping_sub(1)
                    };
                    self.notify.insert(Notify::CONNECTED);
                    self.notify.insert(Notify::WRITABLE);
                }
                // the lowest seen RTT can be used to clamp the delay within
                // reasonable bounds. The one-way delay is never higher than
                // the round-trip time.
                if sample != 0 && acked_bytes != 0 && prev_bytes_in_flight != 0 {
                    // only use the minimum from the last 3 delay measurements
                    delay = *self.delay_sample_hist.iter().min().unwrap_or(&delay);
                    // it's impossible for delay to be more than the RTT, so
                    // make sure to clamp it as a sanity check
                    if delay > min_rtt {
                        delay = min_rtt;
                    }
                    self.do_ledbat(acked_bytes, delay as i64, prev_bytes_in_flight);
                    self.stats.send_delay_us = delay;
                }
                self.stats.recv_delay_us = their_delay.min(min_rtt);

                self.consume_incoming_data(&h, payload);

                // the parameter to send_pkt tells it if we're acking data. If
                // we are, we'll send an ACK regardless of if we have any
                // space left in our send window or not. If we just got an ACK
                // (i.e. ST_STATE) we're not ACKing anything. If we just
                // received a FIN packet, we need to ack that as well
                let has_ack =
                    h.ty == PacketType::Data || h.ty == PacketType::Fin || h.ty == PacketType::Syn;
                let prev_out_packets = self.stats.out_packets;

                // the connection is connected and this packet made it past
                // all the checks. We can now assume the other end is not
                // spoofing its IP.
                if h.ty != PacketType::Syn {
                    self.confirmed = true;
                }

                // try to send more data as long as we can
                while self.send_pkt(0, now) {}

                if has_ack && prev_out_packets == self.stats.out_packets {
                    // we need to ack some data we received, and we didn't
                    // end up sending any payload packets in the loop above.
                    // This means we need to send an ack. don't do it right
                    // away, because we may still receive more packets. defer
                    // the ack to send as few acks as possible
                    self.defer_ack();
                }
            }
            State::FinSent => {
                // we should still ack any incoming data to prevent potential
                // timeouts/resends at the other end
                if h.ty == PacketType::Data {
                    self.defer_ack();
                }
                if self.consume_incoming_data(&h, payload) {
                    return true;
                }
                // we don't increment m_seq_nr when sending a FIN, so we
                // actually need to wait for m_acked_seq_nr to reach m_seq_nr
                // before the FIN is considered ACKed
                if self.acked_seq_nr == self.seq_nr {
                    // When this happens we know that the remote side has
                    // received all of our packets.
                    self.set_error(Error::Eof);
                }
            }
            State::Closed => {
                // respond with a reset
                self.send_reset(h.seq_nr, now, rng);
            }
        }
        true
    }

    fn do_ledbat(&mut self, acked_bytes: i32, delay: i64, in_flight: i32) {
        // the portion of the in-flight bytes that were acked. This is used to
        // make the gain factor be scaled by the rtt. The formula is applied
        // once per rtt, or on every ACK scaled by the number of ACKs per rtt
        let target_delay = i64::from(self.cfg.target_delay_ms).max(1) * 1000;
        // true if the upper layer is pushing enough data down the socket to
        // be limited by the cwnd. If this is not the case, we should not
        // adjust cwnd.
        let cwnd_saturated =
            i64::from(self.bytes_in_flight) + i64::from(acked_bytes) + i64::from(self.mtu)
                > (self.cwnd >> 16);

        // all of these are fixed points with 16 bits fraction portion
        let window_factor = (i64::from(acked_bytes) << 16) / i64::from(in_flight.max(1));
        let delay_factor = ((target_delay - delay) << 16) / target_delay;

        if delay >= target_delay && self.slow_start {
            self.ssthres = ((self.cwnd >> 16) / 2) as i32;
            self.slow_start = false;
        }

        let linear_gain = ((window_factor * delay_factor) >> 16) * self.cfg.gain_factor;

        // if the user is not saturating the link (i.e. not filling the
        // congestion window), don't adjust it at all.
        let mut scaled_gain = if cwnd_saturated {
            let exponential_gain = i64::from(acked_bytes) << 16;
            if self.slow_start {
                // mimic TCP slow-start by adding the number of acked bytes to
                // cwnd
                if self.ssthres != 0
                    && ((self.cwnd + exponential_gain) >> 16) > i64::from(self.ssthres)
                {
                    // if we would exceed the slow start threshold by growing
                    // the cwnd exponentially, don't do it, and leave
                    // slow-start mode. This make us avoid causing more delay
                    // and/or packet loss by being too aggressive
                    self.slow_start = false;
                    linear_gain
                } else {
                    exponential_gain.max(linear_gain)
                }
            } else {
                linear_gain
            }
        } else {
            0
        };

        // make sure we don't wrap the cwnd
        if scaled_gain >= i64::MAX - self.cwnd {
            scaled_gain = i64::MAX - self.cwnd - 1;
        }

        // don't drop below 1*MSS. This behavior is from rfc6817 (LEDBAT).
        // This differs from BEP 29 which allows cwnd to drop to 0, however
        // this way avoids needing to wait until the next timeout to resume
        // sending.
        if (self.cwnd + scaled_gain) >> 16 < i64::from(self.mtu) {
            self.cwnd = i64::from(self.mtu) << 16;
        } else {
            self.cwnd += scaled_gain;
        }

        let window_size_left = i64::min(self.cwnd >> 16, i64::from(self.adv_wnd))
            - i64::from(in_flight)
            + i64::from(acked_bytes);
        if window_size_left >= i64::from(self.mtu) {
            self.cwnd_full = false;
        }
    }

    /// Milliseconds a packet sent now would have before timing out.
    fn packet_timeout(&self) -> u32 {
        // SYN packets have a bit longer timeout, since we don't have an RTT
        // estimate yet, make a conservative guess
        if self.state == State::None {
            return 3000;
        }
        // avoid overflow by simply capping based on number of timeouts as
        // well
        if self.num_timeouts >= 7 {
            return 60_000;
        }
        let mut timeout =
            i64::from(self.cfg.min_timeout_ms).max(self.rtt.mean() + self.rtt.avg_deviation() * 2);
        if self.num_timeouts > 0 {
            timeout += (1i64 << (i64::from(self.num_timeouts) - 1)) * 1000;
        }
        // timeouts over 1 minute are capped
        u32::try_from(timeout.min(60_000)).unwrap_or(60_000)
    }

    /// Drive timeouts; call at [`Socket::next_timeout`] (or more often).
    pub fn tick(&mut self, now: Instant) {
        // if we're already in an error state, we're just waiting for the
        // client to perform an operation so that we can communicate the
        // error. No need to do anything else with this socket
        if self.state == State::Closed {
            return;
        }
        if now <= self.timeout {
            return;
        }
        // TIMEOUT!
        let mut ignore_loss = false;
        if self.acked_seq_nr.wrapping_add(1) == self.mtu_seq
            && self.seq_nr.wrapping_sub(1) == self.mtu_seq
            && self.mtu_seq != 0
        {
            // we timed out, and the only outstanding packet we had was the
            // probe. Assume it was dropped because it was too big
            self.mtu_ceiling = self.mtu.saturating_sub(1);
            self.update_mtu_limits();
            ignore_loss = true;
        }

        // the close_reason here is a bit of a hack. When it's set, it
        // indicates that the upper layer intends to close the socket.
        if !self.outbuf.is_empty() || self.close_reason != 0 {
            // m_num_timeouts is used to update the connection timeout, and if
            // we lose this packet because it's an MTU-probe, don't change the
            // timeout
            if !ignore_loss {
                self.num_timeouts = self.num_timeouts.saturating_add(1);
            }
            self.stats.timeouts += 1;
        }

        // a socket that has not been confirmed to actually have a live remote
        // end (the IP may have been spoofed) fail on the first timeout. If we
        // had heard anything from this peer, it would have been confirmed.
        if self.num_timeouts > self.cfg.num_resends || (self.num_timeouts > 0 && !self.confirmed) {
            // the connection is dead
            self.set_error(Error::TimedOut);
            return;
        }

        if !ignore_loss {
            // set cwnd to 1 MSS
            if self.bytes_in_flight == 0 && (self.cwnd >> 16) >= i64::from(self.mtu) {
                // this is just a timeout because this direction of the
                // stream is idle. Don't reset the cwnd, just decay it
                self.cwnd = i64::max(self.cwnd * 2 / 3, i64::from(self.mtu) << 16);
            } else {
                // we timed out because a packet was not ACKed or because the
                // cwnd was made smaller than one packet
                self.cwnd = i64::from(self.mtu) << 16;
            }
            self.timeout = now + Duration::from_millis(u64::from(self.packet_timeout()));
            // since we've already timed out now, don't count loss that we
            // might detect for packets that just timed out
            self.loss_seq_nr = self.seq_nr;
            // when we time out, the cwnd is reset to 1 MSS, which means we
            // need to ramp it up quickly again. enter slow start mode. This
            // time we're very likely to have an ssthres set, which will make
            // us leave slow start before inducing more delay or loss.
            self.slow_start = true;
        }

        // we dropped all packets, that includes the mtu probe
        self.mtu_seq = 0;

        // we need to go one past m_seq_nr to cover the case where we just
        // sent a SYN packet and then adjusted for the uTorrent sequence
        // number reuse
        let mut i = self.acked_seq_nr;
        let end = self.seq_nr.wrapping_add(1);
        while i != end {
            if let Some(p) = self.outbuf.at_mut(i)
                && !p.need_resend
            {
                p.need_resend = true;
                let payload = p.payload();
                if i != self.acked_seq_nr && i != self.seq_nr {
                    self.needs_resend.push(i);
                }
                self.bytes_in_flight -= payload;
            }
            i = i.wrapping_add(1);
        }

        // if we have a packet that needs re-sending, resend it
        let next = self.acked_seq_nr.wrapping_add(1);
        if let Some(p) = self.outbuf.at(next) {
            let n = p.num_transmissions;
            let size = p.size();
            if n >= self.cfg.num_resends
                || (self.state == State::SynSent && n >= self.cfg.syn_resends)
                || (self.state == State::FinSent && n >= self.cfg.fin_resends)
            {
                if size > self.mtu_floor {
                    // the packet that caused the connection to fail was an
                    // mtu probe (note that the mtu_probe field won't be set
                    // at this point because it's cleared when the packet is
                    // re-sent). This suggests that perhaps our network throws
                    // away oversized packets without fragmenting them. Tell
                    // the socket manager to be more conservative about mtu
                    // ceiling in the future
                    self.restrict_mtu_hint = Some(self.mtu);
                }
                // the connection is dead
                self.set_error(Error::TimedOut);
                return;
            }
            // don't fast-resend this packet
            if self.fast_resend_seq_nr == next {
                self.fast_resend_seq_nr = self.fast_resend_seq_nr.wrapping_add(1);
            }
            // the packet timed out, resend it
            self.resend_packet(next, false, now);
        } else if self.state < State::FinSent {
            self.send_pkt(0, now);
        } else if self.state == State::FinSent {
            // the connection is dead
            self.set_error(Error::Eof);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    struct TestRng(u32);
    impl Rng for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            self.0
        }
    }

    #[test]
    fn syn_shape_matches_the_oracle() {
        let now = Instant::now();
        let clock = Clock::new(now, 1_000_000);
        let mut rng = TestRng(7);
        let a: SocketAddr = "10.1.0.1:6881".parse().unwrap();
        let mut s = Socket::connect(Config::default(), clock, a, 0x1234, 1472, now, &mut rng);
        let syn = s.poll_outgoing().unwrap();
        assert!(!syn.mtu_probe);
        assert_eq!(syn.data.len(), 20);
        let h = Header::parse(&syn.data).unwrap();
        assert_eq!(h.ty, PacketType::Syn);
        assert_eq!(h.extension, 0);
        assert_eq!(h.connection_id, 0x1233); // recv_id = send_id - 1
        assert_eq!(h.wnd_size, 0);
        assert_eq!(h.ack_nr, 0);
        assert_eq!(h.timestamp_diff_us, 0);
        assert_eq!(h.timestamp_us, 1_000_000);
        assert_eq!(s.state(), State::SynSent);
        assert_eq!(s.send_id(), 0x1234);
        assert_eq!(s.recv_id(), 0x1233);
        // Initial MTU search space for v4: floor 548, ceiling 1472, mid 1010.
        assert_eq!(s.mtu(), 1010);
    }

    #[test]
    fn mtu_for_dest() {
        let v4: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let v6: SocketAddr = "[fd00::1]:1".parse().unwrap();
        let teredo: SocketAddr = "[2001:0:1::1]:1".parse().unwrap();
        assert_eq!(Socket::mtu_for_dest(v4, u16::MAX), 1472);
        assert_eq!(Socket::mtu_for_dest(v6, u16::MAX), 1452);
        assert_eq!(Socket::mtu_for_dest(teredo, u16::MAX), 1232);
        assert_eq!(Socket::mtu_for_dest(v4, 1200), 1200);
    }
}
