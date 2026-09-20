// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The per-connection state machine. It owns the framer, both sides'
//! choke/interest flags, the peer's have-set, our outstanding requests and the
//! peer's queued requests, and it enforces what a well-behaved peer may send in
//! each state. It never performs I/O: feed it bytes with [`Connection::receive`]
//! and drain what it wants sent with [`Connection::take_outbound`].

use std::net::IpAddr;

use metainfo::{Bitfield, InfoHash};

use crate::Error;
use crate::framer::Framer;
use crate::handshake::{HANDSHAKE_LEN, Handshake};
use crate::ltep::{EXT_HANDSHAKE_ID, ExtHandshake};
use crate::message::{MAX_BLOCK, Message, Request};

/// Which side opened the TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// We connected out; we send our handshake first.
    Initiator,
    /// The peer connected to us; we answer its handshake.
    Responder,
}

/// What the peer has told us about its pieces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerHave {
    /// Nothing said yet (treated as having nothing).
    Unknown,
    /// `have_none`, or a bitfield/have set over a known piece count.
    Pieces(Bitfield),
    /// `have_all`.
    All,
    /// A bitfield received before the piece count is known (magnet, M6):
    /// kept raw until the metadata arrives.
    Raw(Vec<u8>),
}

impl PeerHave {
    /// Whether the peer has piece `i`.
    pub fn has(&self, i: usize) -> bool {
        match self {
            PeerHave::Unknown | PeerHave::Raw(_) => false,
            PeerHave::All => true,
            PeerHave::Pieces(b) => b.get(i),
        }
    }

    /// A bitfield view over `piece_count` pieces.
    pub fn to_bitfield(&self, piece_count: usize) -> Bitfield {
        match self {
            PeerHave::Unknown | PeerHave::Raw(_) => Bitfield::new(piece_count),
            PeerHave::All => Bitfield::all_set(piece_count),
            PeerHave::Pieces(b) => b.clone(),
        }
    }

    /// Whether the peer claims every piece.
    pub fn is_seed(&self, piece_count: usize) -> bool {
        match self {
            PeerHave::All => true,
            PeerHave::Pieces(b) => piece_count > 0 && b.is_complete(),
            _ => false,
        }
    }
}

/// Everything the connection needs to know about us and the torrent.
#[derive(Debug, Clone)]
pub struct ConnectionParams {
    /// Who opened the connection.
    pub role: Role,
    /// The torrent (must match the peer's handshake).
    pub info_hash: InfoHash,
    /// Our peer id (generated from the profile by the session).
    pub our_peer_id: [u8; 20],
    /// The identity profile (reserved bits, LTEP shape, first messages).
    pub profile: profile::Profile,
    /// Number of pieces, if the metadata is known.
    pub piece_count: Option<usize>,
    /// Our have-set at connection time (for the first-messages sequence).
    pub our_have: Bitfield,
    /// Our listen port (LTEP `p`).
    pub listen_port: u16,
    /// The peer's address as we see it (LTEP `yourip`).
    pub peer_ip: Option<IpAddr>,
    /// Size of the info dictionary (LTEP `metadata_size`), if known.
    pub metadata_size: Option<u32>,
}

/// Something that happened on the connection that the caller must act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Both handshakes are done; the connection is established.
    Handshaked {
        /// The peer's id.
        peer_id: [u8; 20],
        /// The peer's reserved bytes.
        reserved: [u8; 8],
    },
    /// The peer's LTEP handshake arrived.
    ExtHandshake(ExtHandshake),
    /// The peer choked us. `dropped` are our requests that are now void
    /// (empty when the fast extension is on: the peer must `reject` them).
    Choked {
        /// Requests voided by this choke.
        dropped: Vec<Request>,
    },
    /// The peer unchoked us.
    Unchoked,
    /// The peer is interested in our pieces.
    Interested,
    /// The peer is no longer interested.
    NotInterested,
    /// The peer's have-set changed (`have`, `bitfield`, `have_all`,
    /// `have_none`); inspect [`Connection::peer_have`].
    HaveChanged,
    /// A block we requested arrived.
    Block {
        /// The request it satisfies.
        request: Request,
        /// The payload.
        data: Vec<u8>,
    },
    /// A block arrived that we did not request (or requested and then
    /// cancelled): counts as wasted bytes.
    UnexpectedBlock {
        /// Piece index.
        index: u32,
        /// Offset.
        begin: u32,
        /// Payload length.
        length: u32,
    },
    /// The peer requested a block and we are not choking it (or the piece is
    /// in its allowed-fast set). The caller serves or rejects it.
    Request(Request),
    /// The peer cancelled a request.
    Cancel(Request),
    /// The peer rejected one of our requests (fast extension).
    Rejected(Request),
    /// The peer granted allowed-fast for a piece.
    AllowedFast(u32),
    /// The peer suggests a piece.
    Suggest(u32),
    /// A non-handshake extended message (BEP 11 PEX, BEP 9 metadata, ...).
    Extended {
        /// The id *we* assigned to the extension in our `m`.
        id: u8,
        /// Payload.
        payload: Vec<u8>,
    },
    /// The peer sent `port` (DHT). Ignored by 0.1.0 (docs/quirks.md Q1).
    Port(u16),
    /// A keep-alive arrived.
    KeepAlive,
}

/// Upper bound on requests we keep outstanding towards a peer (protects the
/// bookkeeping; the actual pipeline depth is the caller's policy).
const MAX_OUTSTANDING: usize = 2048;

/// Upper bound on queued requests from a peer before we start rejecting /
/// disconnecting (libtorrent disconnects above `max_allowed_in_request_queue`).
const MAX_INCOMING_HARD: usize = 4096;

/// The connection state machine.
pub struct Connection {
    params: ConnectionParams,
    framer: Framer,
    outbound: Vec<u8>,
    established: bool,
    sent_handshake: bool,
    peer_handshake: Option<Handshake>,
    ltep: bool,
    fast: bool,
    peer_ext: Option<ExtHandshake>,
    am_choking: bool,
    am_interested: bool,
    peer_choking: bool,
    peer_interested: bool,
    peer_have: PeerHave,
    outstanding: Vec<Request>,
    incoming: Vec<Request>,
    allowed_fast_in: Vec<u32>,
    allowed_fast_out: Vec<u32>,
    payload_in: u64,
    payload_out: u64,
    wasted_in: u64,
}

impl Connection {
    /// Create a connection. An initiator immediately queues its handshake in
    /// the outbound buffer; a responder waits for the peer's.
    pub fn new(params: ConnectionParams) -> Connection {
        let mut c = Connection {
            framer: Framer::new(),
            outbound: Vec::with_capacity(256),
            established: false,
            sent_handshake: false,
            peer_handshake: None,
            ltep: false,
            fast: false,
            peer_ext: None,
            am_choking: true,
            am_interested: false,
            peer_choking: true,
            peer_interested: false,
            peer_have: PeerHave::Unknown,
            outstanding: Vec::new(),
            incoming: Vec::new(),
            allowed_fast_in: Vec::new(),
            allowed_fast_out: Vec::new(),
            payload_in: 0,
            payload_out: 0,
            wasted_in: 0,
            params,
        };
        if c.params.role == Role::Initiator {
            c.send_handshake();
        }
        c
    }

    fn send_handshake(&mut self) {
        let hs = Handshake {
            reserved: self.params.profile.peer.reserved,
            info_hash: self.params.info_hash,
            peer_id: self.params.our_peer_id,
        };
        self.outbound.extend_from_slice(&hs.encode());
        self.sent_handshake = true;
    }

    // --- accessors ---

    /// The parameters this connection was created with.
    pub fn params(&self) -> &ConnectionParams {
        &self.params
    }
    /// Whether both handshakes completed.
    pub fn is_established(&self) -> bool {
        self.established
    }
    /// The peer's handshake, once received.
    pub fn peer_handshake(&self) -> Option<&Handshake> {
        self.peer_handshake.as_ref()
    }
    /// The peer's LTEP handshake, once received.
    pub fn peer_ext(&self) -> Option<&ExtHandshake> {
        self.peer_ext.as_ref()
    }
    /// Whether LTEP was negotiated (both sides set the bit).
    pub fn ltep(&self) -> bool {
        self.ltep
    }
    /// Whether the fast extension was negotiated.
    pub fn fast(&self) -> bool {
        self.fast
    }
    /// Are we choking the peer?
    pub fn am_choking(&self) -> bool {
        self.am_choking
    }
    /// Are we interested in the peer?
    pub fn am_interested(&self) -> bool {
        self.am_interested
    }
    /// Is the peer choking us?
    pub fn peer_choking(&self) -> bool {
        self.peer_choking
    }
    /// Is the peer interested in us?
    pub fn peer_interested(&self) -> bool {
        self.peer_interested
    }
    /// What the peer has.
    pub fn peer_have(&self) -> &PeerHave {
        &self.peer_have
    }
    /// Our requests the peer has not answered yet.
    pub fn outstanding(&self) -> &[Request] {
        &self.outstanding
    }
    /// The peer's requests we have not answered yet.
    pub fn incoming_requests(&self) -> &[Request] {
        &self.incoming
    }
    /// Pieces the peer allowed us to request while choked.
    pub fn allowed_fast(&self) -> &[u32] {
        &self.allowed_fast_in
    }
    /// Payload bytes received in `piece` messages we requested.
    pub fn payload_in(&self) -> u64 {
        self.payload_in
    }
    /// Payload bytes we sent in `piece` messages.
    pub fn payload_out(&self) -> u64 {
        self.payload_out
    }
    /// Payload bytes received that we did not want (redundant/wasted).
    pub fn wasted_in(&self) -> u64 {
        self.wasted_in
    }
    /// Whether we can request piece `index` right now: unchoked, or the piece
    /// is in our allowed-fast set.
    pub fn can_request(&self, index: u32) -> bool {
        self.established && (!self.peer_choking || self.allowed_fast_in.contains(&index))
    }

    /// Take everything queued for sending. The caller writes it to the socket.
    pub fn take_outbound(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outbound)
    }

    /// Whether there are bytes queued for sending.
    pub fn has_outbound(&self) -> bool {
        !self.outbound.is_empty()
    }

    // --- outgoing actions ---

    fn push(&mut self, m: &Message) {
        m.encode(&mut self.outbound);
    }

    /// Queue a keep-alive.
    pub fn keep_alive(&mut self) {
        self.push(&Message::KeepAlive);
    }

    /// Choke or unchoke the peer. Choking with the fast extension rejects
    /// every queued request (BEP 6); without it the queue is simply dropped
    /// (the peer knows to re-request).
    pub fn choke(&mut self, choke: bool) {
        if self.am_choking == choke {
            return;
        }
        self.am_choking = choke;
        self.push(if choke {
            &Message::Choke
        } else {
            &Message::Unchoke
        });
        if choke {
            let queued = std::mem::take(&mut self.incoming);
            if self.fast {
                for r in queued {
                    self.push(&Message::Reject(r));
                }
            }
        }
    }

    /// Declare interest (or not) in the peer's pieces.
    pub fn interested(&mut self, interested: bool) {
        if self.am_interested == interested {
            return;
        }
        self.am_interested = interested;
        self.push(if interested {
            &Message::Interested
        } else {
            &Message::NotInterested
        });
    }

    /// Announce that we now have piece `index`.
    pub fn have(&mut self, index: u32) {
        self.push(&Message::Have(index));
    }

    /// Request a block. Returns `false` (and sends nothing) if the request is
    /// not allowed right now (choked without allowed-fast, too many
    /// outstanding, or a duplicate).
    pub fn request(&mut self, r: Request) -> bool {
        if !self.can_request(r.index)
            || self.outstanding.len() >= MAX_OUTSTANDING
            || self.outstanding.contains(&r)
        {
            return false;
        }
        self.outstanding.push(r);
        self.push(&Message::Request(r));
        true
    }

    /// Cancel an outstanding request.
    pub fn cancel(&mut self, r: Request) {
        if let Some(pos) = self.outstanding.iter().position(|x| *x == r) {
            self.outstanding.remove(pos);
            self.push(&Message::Cancel(r));
        }
    }

    /// Forget every outstanding request without telling the peer (used when
    /// the connection is being closed).
    pub fn drain_outstanding(&mut self) -> Vec<Request> {
        std::mem::take(&mut self.outstanding)
    }

    /// Send a block the peer requested. Removes it from the incoming queue.
    pub fn piece(&mut self, r: Request, data: &[u8]) {
        if let Some(pos) = self.incoming.iter().position(|x| *x == r) {
            self.incoming.remove(pos);
        }
        self.payload_out += data.len() as u64;
        self.push(&Message::Piece {
            index: r.index,
            begin: r.begin,
            data: data.to_vec(),
        });
    }

    /// Reject a request the peer made (fast extension only; a no-op without
    /// it, where silence is the protocol).
    pub fn reject(&mut self, r: Request) {
        if let Some(pos) = self.incoming.iter().position(|x| *x == r) {
            self.incoming.remove(pos);
        }
        if self.fast {
            self.push(&Message::Reject(r));
        }
    }

    /// Grant allowed-fast for `index` (fast extension only).
    pub fn allow_fast(&mut self, index: u32) {
        if self.fast && !self.allowed_fast_out.contains(&index) {
            self.allowed_fast_out.push(index);
            self.push(&Message::AllowedFast(index));
        }
    }

    /// Send an extended message under the id the *peer* assigned to `name`.
    /// Returns `false` if the peer did not advertise the extension.
    pub fn extended(&mut self, name: &str, payload: &[u8]) -> bool {
        let Some(id) = self.peer_ext.as_ref().and_then(|e| e.peer_id_for(name)) else {
            return false;
        };
        self.push(&Message::Extended {
            id,
            payload: payload.to_vec(),
        });
        true
    }

    // --- incoming ---

    /// Feed received bytes. Returns the events they produced, in order, or an
    /// error meaning the peer must be disconnected.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<Vec<Event>, Error> {
        self.framer.push(bytes)?;
        let mut events = Vec::new();
        if !self.established {
            let hs = match Handshake::parse(self.framer.pending())? {
                Some(hs) => hs,
                None => return Ok(events),
            };
            self.framer.consume(HANDSHAKE_LEN);
            self.on_handshake(hs, &mut events)?;
        }
        while let Some(body) = self.framer.next_frame()? {
            let msg = Message::decode(body)?;
            self.on_message(msg, &mut events)?;
        }
        Ok(events)
    }

    fn on_handshake(&mut self, hs: Handshake, events: &mut Vec<Event>) -> Result<(), Error> {
        if hs.info_hash != self.params.info_hash {
            return Err(Error::InfoHashMismatch);
        }
        if hs.peer_id == self.params.our_peer_id {
            return Err(Error::Protocol("connected to ourselves"));
        }
        self.ltep = hs.supports_ltep() && self.params.profile.supports_ltep();
        self.fast = hs.supports_fast() && self.params.profile.supports_fast();
        events.push(Event::Handshaked {
            peer_id: hs.peer_id,
            reserved: hs.reserved,
        });
        self.peer_handshake = Some(hs);
        if !self.sent_handshake {
            self.send_handshake();
        }
        self.established = true;
        self.send_first_messages();
        Ok(())
    }

    /// The first-messages sequence after the handshake, in profile order.
    fn send_first_messages(&mut self) {
        let outgoing = self.params.role == Role::Initiator;
        for step in self.params.profile.peer.first_messages {
            match step {
                profile::FirstMessage::ExtendedHandshake => {
                    if self.ltep {
                        let seeding = self
                            .params
                            .piece_count
                            .is_some_and(|n| n > 0 && self.params.our_have.is_complete());
                        let ext = ExtHandshake::build(
                            &self.params.profile.ltep,
                            self.params.profile.ltep_version,
                            outgoing,
                            self.params.listen_port,
                            self.params.peer_ip,
                            self.params.metadata_size,
                            seeding,
                        );
                        let payload = ext.encode();
                        self.push(&Message::Extended {
                            id: EXT_HANDSHAKE_ID,
                            payload,
                        });
                    }
                }
                profile::FirstMessage::HaveState => {
                    let Some(n) = self.params.piece_count else {
                        // No metadata yet: nothing to say about pieces. With
                        // the fast extension, `have_none` is still valid.
                        if self.fast {
                            self.push(&Message::HaveNone);
                        }
                        continue;
                    };
                    let have = &self.params.our_have;
                    if self.fast && n > 0 && have.is_complete() {
                        self.push(&Message::HaveAll);
                    } else if self.fast && have.count() == 0 {
                        self.push(&Message::HaveNone);
                    } else {
                        let m = Message::Bitfield(have.as_bytes().to_vec());
                        self.push(&m);
                    }
                }
            }
        }
    }

    fn check_index(&self, index: u32) -> Result<(), Error> {
        match self.params.piece_count {
            Some(n) if (index as usize) < n => Ok(()),
            Some(_) => Err(Error::Protocol("piece index out of range")),
            None => Ok(()),
        }
    }

    fn check_block(&self, r: &Request) -> Result<(), Error> {
        self.check_index(r.index)?;
        if r.length == 0 || r.length > MAX_BLOCK {
            return Err(Error::Protocol("bad block length"));
        }
        if r.begin.checked_add(r.length).is_none() {
            return Err(Error::Protocol("block offset overflow"));
        }
        Ok(())
    }

    fn need_fast(&self) -> Result<(), Error> {
        if self.fast {
            Ok(())
        } else {
            Err(Error::Protocol(
                "fast-extension message without the extension",
            ))
        }
    }

    fn peer_pieces_mut(&mut self) -> Option<&mut Bitfield> {
        let n = self.params.piece_count?;
        if !matches!(self.peer_have, PeerHave::Pieces(_)) {
            self.peer_have = PeerHave::Pieces(Bitfield::new(n));
        }
        match &mut self.peer_have {
            PeerHave::Pieces(b) => Some(b),
            _ => None,
        }
    }

    fn on_message(&mut self, msg: Message, events: &mut Vec<Event>) -> Result<(), Error> {
        match msg {
            Message::KeepAlive => events.push(Event::KeepAlive),
            Message::Choke => {
                self.peer_choking = true;
                let dropped = if self.fast {
                    Vec::new()
                } else {
                    std::mem::take(&mut self.outstanding)
                };
                events.push(Event::Choked { dropped });
            }
            Message::Unchoke => {
                self.peer_choking = false;
                events.push(Event::Unchoked);
            }
            Message::Interested => {
                self.peer_interested = true;
                events.push(Event::Interested);
            }
            Message::NotInterested => {
                self.peer_interested = false;
                events.push(Event::NotInterested);
            }
            Message::Have(i) => {
                self.check_index(i)?;
                match &mut self.peer_have {
                    PeerHave::All => {}
                    PeerHave::Raw(_) => {} // cannot apply until metadata is known
                    _ => {
                        if let Some(b) = self.peer_pieces_mut() {
                            b.set(i as usize);
                        }
                    }
                }
                events.push(Event::HaveChanged);
            }
            Message::Bitfield(bytes) => {
                match self.params.piece_count {
                    Some(n) => {
                        let bf = Bitfield::from_bytes(&bytes, n)
                            .ok_or(Error::Protocol("bitfield length mismatch"))?;
                        self.peer_have = PeerHave::Pieces(bf);
                    }
                    None => self.peer_have = PeerHave::Raw(bytes),
                }
                events.push(Event::HaveChanged);
            }
            Message::HaveAll => {
                self.need_fast()?;
                self.peer_have = PeerHave::All;
                events.push(Event::HaveChanged);
            }
            Message::HaveNone => {
                self.need_fast()?;
                self.peer_have = match self.params.piece_count {
                    Some(n) => PeerHave::Pieces(Bitfield::new(n)),
                    None => PeerHave::Raw(Vec::new()),
                };
                events.push(Event::HaveChanged);
            }
            Message::Request(r) => {
                self.check_block(&r)?;
                if self.am_choking && !self.allowed_fast_out.contains(&r.index) {
                    // Requests while choked: reject with fast, ignore without.
                    if self.fast {
                        self.push(&Message::Reject(r));
                    }
                    return Ok(());
                }
                if self.incoming.len() >= MAX_INCOMING_HARD {
                    return Err(Error::Protocol("request queue overflow"));
                }
                if !self.incoming.contains(&r) {
                    self.incoming.push(r);
                }
                events.push(Event::Request(r));
            }
            Message::Piece { index, begin, data } => {
                self.check_index(index)?;
                let length = data.len() as u32;
                let r = Request {
                    index,
                    begin,
                    length,
                };
                if let Some(pos) = self.outstanding.iter().position(|x| *x == r) {
                    self.outstanding.remove(pos);
                    self.payload_in += u64::from(length);
                    events.push(Event::Block { request: r, data });
                } else {
                    self.wasted_in += u64::from(length);
                    events.push(Event::UnexpectedBlock {
                        index,
                        begin,
                        length,
                    });
                }
            }
            Message::Cancel(r) => {
                self.check_block(&r)?;
                if let Some(pos) = self.incoming.iter().position(|x| *x == r) {
                    self.incoming.remove(pos);
                    events.push(Event::Cancel(r));
                }
            }
            Message::Port(p) => events.push(Event::Port(p)),
            Message::Suggest(i) => {
                self.need_fast()?;
                self.check_index(i)?;
                events.push(Event::Suggest(i));
            }
            Message::Reject(r) => {
                self.need_fast()?;
                self.check_block(&r)?;
                if let Some(pos) = self.outstanding.iter().position(|x| *x == r) {
                    self.outstanding.remove(pos);
                    events.push(Event::Rejected(r));
                }
            }
            Message::AllowedFast(i) => {
                self.need_fast()?;
                self.check_index(i)?;
                if !self.allowed_fast_in.contains(&i) && self.allowed_fast_in.len() < 1024 {
                    self.allowed_fast_in.push(i);
                }
                events.push(Event::AllowedFast(i));
            }
            Message::Extended { id, payload } => {
                if !self.ltep {
                    return Err(Error::Protocol("extended message without LTEP"));
                }
                if id == EXT_HANDSHAKE_ID {
                    let ext = ExtHandshake::parse(&payload)?;
                    self.peer_ext = Some(ext.clone());
                    events.push(Event::ExtHandshake(ext));
                } else {
                    events.push(Event::Extended { id, payload });
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(role: Role, pieces: usize, have_all: bool) -> ConnectionParams {
        ConnectionParams {
            role,
            info_hash: [1; 20],
            our_peer_id: *b"-UR0010-000000000000",
            profile: profile::Profile::native(),
            piece_count: Some(pieces),
            our_have: if have_all {
                Bitfield::all_set(pieces)
            } else {
                Bitfield::new(pieces)
            },
            listen_port: 6881,
            peer_ip: Some("10.0.0.2".parse().unwrap()),
            metadata_size: Some(100),
        }
    }

    fn peer_hs(reserved: [u8; 8]) -> Vec<u8> {
        Handshake {
            reserved,
            info_hash: [1; 20],
            peer_id: *b"-XX0000-000000000000",
        }
        .encode()
        .to_vec()
    }

    const FULL: [u8; 8] = [0, 0, 0, 0, 0, 0x10, 0, 0x05];
    const PLAIN: [u8; 8] = [0; 8];

    /// Split a byte stream into decoded messages (skipping a leading handshake).
    fn decode_all(mut bytes: &[u8], skip_hs: bool) -> Vec<Message> {
        if skip_hs {
            bytes = &bytes[HANDSHAKE_LEN..];
        }
        let mut f = Framer::new();
        f.push(bytes).unwrap();
        let mut out = Vec::new();
        while let Some(body) = f.next_frame().unwrap() {
            out.push(Message::decode(body).unwrap());
        }
        out
    }

    #[test]
    fn initiator_handshake_then_first_messages() {
        let mut c = Connection::new(params(Role::Initiator, 32, false));
        let out = c.take_outbound();
        assert_eq!(out.len(), HANDSHAKE_LEN);
        assert!(!c.is_established());
        let ev = c.receive(&peer_hs(FULL)).unwrap();
        assert!(matches!(ev[0], Event::Handshaked { .. }));
        assert!(c.is_established() && c.ltep() && c.fast());
        let msgs = decode_all(&c.take_outbound(), false);
        assert!(matches!(msgs[0], Message::Extended { id: 0, .. }));
        assert_eq!(msgs[1], Message::HaveNone);
        assert_eq!(msgs.len(), 2);
    }

    #[test]
    fn responder_waits_then_answers() {
        let mut c = Connection::new(params(Role::Responder, 8, true));
        assert!(c.take_outbound().is_empty());
        // Handshake in two halves.
        let hs = peer_hs(FULL);
        assert!(c.receive(&hs[..30]).unwrap().is_empty());
        let ev = c.receive(&hs[30..]).unwrap();
        assert!(matches!(ev[0], Event::Handshaked { .. }));
        let out = c.take_outbound();
        let msgs = decode_all(&out, true);
        assert!(matches!(msgs[0], Message::Extended { id: 0, .. }));
        assert_eq!(msgs[1], Message::HaveAll);
        // Seeding: upload_only is not part of the native profile.
        if let Message::Extended { payload, .. } = &msgs[0] {
            let ext = ExtHandshake::parse(payload).unwrap();
            assert_eq!(ext.upload_only, None);
            assert_eq!(ext.p, Some(6881));
            assert_eq!(ext.yourip, Some("10.0.0.2".parse().unwrap()));
        }
    }

    #[test]
    fn plain_peer_gets_bitfield_and_no_ltep() {
        let mut c = Connection::new(params(Role::Initiator, 12, false));
        c.take_outbound();
        c.receive(&peer_hs(PLAIN)).unwrap();
        assert!(!c.ltep() && !c.fast());
        let msgs = decode_all(&c.take_outbound(), false);
        assert_eq!(msgs, vec![Message::Bitfield(vec![0, 0])]);
        // fast messages from a non-fast peer are violations
        assert!(c.receive(&Message::HaveAll.to_bytes()).is_err());
    }

    #[test]
    fn wrong_info_hash_rejected() {
        let mut c = Connection::new(params(Role::Initiator, 4, false));
        let hs = Handshake {
            reserved: FULL,
            info_hash: [9; 20],
            peer_id: [0; 20],
        };
        assert_eq!(c.receive(&hs.encode()), Err(Error::InfoHashMismatch));
    }

    fn established(pieces: usize) -> Connection {
        let mut c = Connection::new(params(Role::Initiator, pieces, false));
        c.take_outbound();
        c.receive(&peer_hs(FULL)).unwrap();
        c.take_outbound();
        c
    }

    #[test]
    fn request_block_flow() {
        let mut c = established(4);
        let r = Request {
            index: 1,
            begin: 0,
            length: 16384,
        };
        // choked: cannot request
        assert!(!c.request(r));
        let ev = c.receive(&Message::Unchoke.to_bytes()).unwrap();
        assert_eq!(ev, vec![Event::Unchoked]);
        assert!(c.request(r));
        assert!(!c.request(r), "duplicate refused");
        assert_eq!(c.outstanding(), &[r]);
        let msgs = decode_all(&c.take_outbound(), false);
        assert_eq!(msgs, vec![Message::Request(r)]);
        // wrong block arrives -> unexpected
        let ev = c
            .receive(
                &Message::Piece {
                    index: 1,
                    begin: 16384,
                    data: vec![0; 16384],
                }
                .to_bytes(),
            )
            .unwrap();
        assert!(matches!(ev[0], Event::UnexpectedBlock { .. }));
        assert_eq!(c.wasted_in(), 16384);
        // right block arrives
        let ev = c
            .receive(
                &Message::Piece {
                    index: 1,
                    begin: 0,
                    data: vec![7; 16384],
                }
                .to_bytes(),
            )
            .unwrap();
        assert!(
            matches!(&ev[0], Event::Block { request, data } if *request == r && data.len() == 16384)
        );
        assert_eq!(c.payload_in(), 16384);
        assert!(c.outstanding().is_empty());
        // out of range index is a violation
        assert!(c.receive(&Message::Have(4).to_bytes()).is_err());
    }

    #[test]
    fn choke_semantics_with_and_without_fast() {
        let r = Request {
            index: 0,
            begin: 0,
            length: 1024,
        };
        // fast: outstanding survive a choke, are removed by reject
        let mut c = established(2);
        c.receive(&Message::Unchoke.to_bytes()).unwrap();
        assert!(c.request(r));
        let ev = c.receive(&Message::Choke.to_bytes()).unwrap();
        assert_eq!(ev, vec![Event::Choked { dropped: vec![] }]);
        assert_eq!(c.outstanding().len(), 1);
        let ev = c.receive(&Message::Reject(r).to_bytes()).unwrap();
        assert_eq!(ev, vec![Event::Rejected(r)]);
        assert!(c.outstanding().is_empty());
        // allowed fast lets us request while choked
        c.receive(&Message::AllowedFast(1).to_bytes()).unwrap();
        assert!(c.can_request(1) && !c.can_request(0));

        // no fast: choke drops outstanding
        let mut p = Connection::new(params(Role::Initiator, 2, false));
        p.take_outbound();
        p.receive(&peer_hs(PLAIN)).unwrap();
        p.receive(&Message::Unchoke.to_bytes()).unwrap();
        assert!(p.request(r));
        let ev = p.receive(&Message::Choke.to_bytes()).unwrap();
        assert_eq!(ev, vec![Event::Choked { dropped: vec![r] }]);
        assert!(p.outstanding().is_empty());
    }

    #[test]
    fn peer_requests_while_we_choke_are_rejected_with_fast() {
        let mut c = established(2);
        let r = Request {
            index: 0,
            begin: 0,
            length: 16384,
        };
        let ev = c.receive(&Message::Request(r).to_bytes()).unwrap();
        assert!(ev.is_empty());
        let msgs = decode_all(&c.take_outbound(), false);
        assert_eq!(msgs, vec![Message::Reject(r)]);
        // unchoke: request is surfaced and queued
        c.choke(false);
        c.take_outbound();
        let ev = c.receive(&Message::Request(r).to_bytes()).unwrap();
        assert_eq!(ev, vec![Event::Request(r)]);
        assert_eq!(c.incoming_requests(), &[r]);
        c.piece(r, &[1; 16384]);
        assert!(c.incoming_requests().is_empty());
        assert_eq!(c.payload_out(), 16384);
        // choking again rejects queued requests
        c.receive(&Message::Request(r).to_bytes()).unwrap();
        c.take_outbound();
        c.choke(true);
        let msgs = decode_all(&c.take_outbound(), false);
        assert_eq!(msgs, vec![Message::Choke, Message::Reject(r)]);
    }

    #[test]
    fn have_state_tracking() {
        let mut c = established(10);
        c.receive(&Message::Bitfield(vec![0x80, 0x00]).to_bytes())
            .unwrap();
        assert!(c.peer_have().has(0) && !c.peer_have().has(1));
        c.receive(&Message::Have(9).to_bytes()).unwrap();
        assert!(c.peer_have().has(9));
        assert!(!c.peer_have().is_seed(10));
        c.receive(&Message::HaveAll.to_bytes()).unwrap();
        assert!(c.peer_have().is_seed(10));
        // bad bitfield length
        assert!(
            c.receive(&Message::Bitfield(vec![0x80]).to_bytes())
                .is_err()
        );
    }

    #[test]
    fn extended_messages_need_ltep_and_ids_follow_peer_m() {
        let mut c = established(2);
        let ext = ExtHandshake {
            m: vec![("ut_pex".into(), 5)],
            ..Default::default()
        };
        let ev = c
            .receive(
                &Message::Extended {
                    id: 0,
                    payload: ext.encode(),
                }
                .to_bytes(),
            )
            .unwrap();
        assert!(matches!(ev[0], Event::ExtHandshake(_)));
        assert!(c.extended("ut_pex", b"d1:xi1ee"));
        assert!(!c.extended("ut_metadata", b"de"));
        let msgs = decode_all(&c.take_outbound(), false);
        assert_eq!(
            msgs,
            vec![Message::Extended {
                id: 5,
                payload: b"d1:xi1ee".to_vec()
            }]
        );
        let ev = c
            .receive(
                &Message::Extended {
                    id: 3,
                    payload: vec![1],
                }
                .to_bytes(),
            )
            .unwrap();
        assert_eq!(
            ev,
            vec![Event::Extended {
                id: 3,
                payload: vec![1]
            }]
        );
        // without LTEP negotiated: violation
        let mut p = Connection::new(params(Role::Initiator, 2, false));
        p.take_outbound();
        p.receive(&peer_hs(PLAIN)).unwrap();
        assert!(
            p.receive(
                &Message::Extended {
                    id: 0,
                    payload: b"de".to_vec()
                }
                .to_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn self_connection_detected() {
        let mut c = Connection::new(params(Role::Initiator, 2, false));
        let hs = Handshake {
            reserved: FULL,
            info_hash: [1; 20],
            peer_id: *b"-UR0010-000000000000",
        };
        assert!(c.receive(&hs.encode()).is_err());
    }
}
