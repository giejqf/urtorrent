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
    /// Whether our listen port is advertisable to this peer (LTEP `p`):
    /// libtorrent only sends it when the listen socket's external address
    /// matches the connection's local address, and a socket without any
    /// external-address vote yet only matches IPv4 (docs/quirks.md Q6). The
    /// session computes this; `true` for a v4 connection with no known
    /// external address, `false` for v6 until one is known.
    pub advertise_port: bool,
    /// BEP 27 private torrent: no PEX / metadata extensions (Q11).
    pub private: bool,
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
    /// The peer's have-set changed; inspect [`Connection::peer_have`].
    HaveChanged {
        /// The single piece a `have` added, when the change was just that
        /// (`None` for `bitfield`, `have_all`, `have_none` and metadata).
        added: Option<u32>,
    },
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
    /// Bytes to send, in order. Control messages accumulate in the last
    /// chunk; a piece payload is its own chunk (the block buffer as read from
    /// disk, never copied), followed by a fresh control chunk.
    outbound: Vec<Vec<u8>>,
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
    /// The allowed-fast set goes out once, on the peer's first `interested`
    /// (libtorrent defers it to skip pieces the peer already has).
    sent_allowed_fast: bool,
    /// Set by [`Connection::set_metadata`]; the have-state is sent then.
    metadata_known: bool,
    /// The peer declared itself upload-only (BEP 21).
    peer_upload_only: bool,
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
            outbound: vec![Vec::with_capacity(256)],
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
            sent_allowed_fast: false,
            metadata_known: params.piece_count.is_some(),
            peer_upload_only: false,
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
        self.control_out().extend_from_slice(&hs.encode());
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
        let chunks = self.take_outbound_chunks();
        match chunks.len() {
            0 => Vec::new(),
            1 => chunks.into_iter().next().unwrap_or_default(),
            _ => chunks.concat(),
        }
    }

    /// Drain the bytes queued for sending as ordered chunks (piece payloads
    /// are separate chunks, so the caller can send them without copying).
    pub fn take_outbound_chunks(&mut self) -> Vec<Vec<u8>> {
        let mut chunks = std::mem::replace(&mut self.outbound, vec![Vec::with_capacity(256)]);
        chunks.retain(|c| !c.is_empty());
        chunks
    }

    /// Whether there are bytes queued for sending.
    pub fn has_outbound(&self) -> bool {
        self.outbound.iter().any(|c| !c.is_empty())
    }

    /// Bytes queued for sending.
    pub fn outbound_len(&self) -> usize {
        self.outbound.iter().map(Vec::len).sum()
    }

    /// The control chunk messages are appended to.
    fn control_out(&mut self) -> &mut Vec<u8> {
        if self.outbound.is_empty() {
            self.outbound.push(Vec::with_capacity(256));
        }
        let last = self.outbound.len() - 1;
        &mut self.outbound[last]
    }

    /// Pieces we granted the peer allowed-fast for.
    pub fn allowed_fast_granted(&self) -> &[u32] {
        &self.allowed_fast_out
    }

    // --- outgoing actions ---

    fn push(&mut self, m: &Message) {
        m.encode(self.control_out());
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
    pub fn piece(&mut self, r: Request, data: Vec<u8>) {
        if let Some(pos) = self.incoming.iter().position(|x| *x == r) {
            self.incoming.remove(pos);
        }
        self.payload_out += data.len() as u64;
        Message::encode_piece_header(self.control_out(), r.index, r.begin, data.len() as u32);
        // The payload travels as its own chunk: no copy into the byte queue.
        self.outbound.push(data);
        self.outbound.push(Vec::with_capacity(256));
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

    /// Record the peer's BEP 21 `upload_only` state (from its LTEP handshake
    /// or an `upload_only` message).
    pub fn set_peer_upload_only(&mut self, on: bool) {
        self.peer_upload_only = on;
    }

    /// Whether the peer declared itself upload-only.
    pub fn peer_upload_only(&self) -> bool {
        self.peer_upload_only
    }

    /// Whether the piece count is known (metadata present).
    pub fn has_metadata(&self) -> bool {
        self.params.piece_count.is_some()
    }

    /// The id *we* assigned to extension `name` (what the peer sends us), per
    /// the profile and the torrent's privacy.
    pub fn our_ext_id(&self, name: &str) -> Option<u8> {
        let m = if self.params.private {
            self.params.profile.ltep.m_private
        } else {
            self.params.profile.ltep.m
        };
        m.iter().find(|e| e.name == name).map(|e| e.id)
    }

    /// Whether the peer advertised extension `name`.
    pub fn peer_supports(&self, name: &str) -> bool {
        self.peer_ext
            .as_ref()
            .is_some_and(|e| e.peer_id_for(name).is_some())
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
                            self.params
                                .advertise_port
                                .then_some(self.params.listen_port),
                            self.params.peer_ip,
                            self.params.metadata_size,
                            seeding,
                            self.params.private,
                        );
                        let payload = ext.encode();
                        self.push(&Message::Extended {
                            id: EXT_HANDSHAKE_ID,
                            payload,
                        });
                    }
                }
                profile::FirstMessage::HaveState => {
                    // Without metadata nothing is said about pieces: libtorrent
                    // sends neither a bitfield nor `have_none` until the
                    // metadata is known (then `set_metadata` does).
                    if self.params.piece_count.is_some() {
                        self.send_have_state();
                    }
                }
            }
        }
    }

    /// `bitfield` / `have_all` / `have_none` for our have-set, libtorrent's
    /// `write_bitfield`: `have_all` for a seed and `have_none` for nothing
    /// with the fast extension, nothing at all for nothing without it, a
    /// `bitfield` otherwise.
    fn send_have_state(&mut self) {
        let Some(n) = self.params.piece_count else {
            return;
        };
        let have = &self.params.our_have;
        if self.fast && n > 0 && have.is_complete() {
            self.push(&Message::HaveAll);
        } else if self.fast && have.count() == 0 {
            self.push(&Message::HaveNone);
        } else if have.count() == 0 {
            // Nothing to announce and no way to say so.
        } else {
            let m = Message::Bitfield(have.as_bytes().to_vec());
            self.push(&m);
        }
    }

    /// The metadata arrived (magnet link): apply the piece count, translate a
    /// bitfield the peer sent before we could size it, and send our have-state
    /// as libtorrent's `on_metadata` does. Returns `HaveChanged` when the
    /// peer's have-set became known.
    pub fn set_metadata(
        &mut self,
        piece_count: usize,
        our_have: Bitfield,
    ) -> Result<Option<Event>, Error> {
        if self.params.piece_count.is_some() {
            return Ok(None);
        }
        self.params.piece_count = Some(piece_count);
        self.params.our_have = our_have;
        self.metadata_known = true;
        let mut ev = None;
        if let PeerHave::Raw(raw) = &self.peer_have {
            if raw.is_empty() {
                self.peer_have = PeerHave::Pieces(Bitfield::new(piece_count));
            } else {
                let bf = Bitfield::from_bytes(raw, piece_count)
                    .ok_or(Error::Protocol("bitfield length mismatch"))?;
                self.peer_have = PeerHave::Pieces(bf);
            }
            ev = Some(Event::HaveChanged { added: None });
        } else if matches!(self.peer_have, PeerHave::All) {
            ev = Some(Event::HaveChanged { added: None });
        }
        if self.established {
            self.send_have_state();
            if self.peer_interested && !self.sent_allowed_fast {
                self.send_allowed_set();
            }
        }
        Ok(ev)
    }

    /// The BEP 6 allowed-fast grants for this peer (libtorrent
    /// `send_allowed_set`): `allowed_fast_count` indices from the canonical
    /// generator, skipping pieces the peer already has; every piece it lacks
    /// when the torrent has no more pieces than that. Nothing without the
    /// fast extension, without metadata, or for an upload-only peer.
    fn send_allowed_set(&mut self) {
        self.sent_allowed_fast = true;
        let k = self.params.profile.peer.allowed_fast_count;
        let (Some(n), Some(ip)) = (self.params.piece_count, self.params.peer_ip) else {
            return;
        };
        if !self.fast || k == 0 || n == 0 || self.peer_upload_only {
            return;
        }
        let peer_has = |c: &Connection, i: u32| c.peer_have.has(i as usize);
        if (k as usize) >= n {
            for i in 0..n as u32 {
                if !peer_has(self, i) {
                    self.allow_fast(i);
                }
            }
            return;
        }
        let set = crate::fast::allowed_fast_set(
            ip,
            &self.params.info_hash,
            n.min(u32::MAX as usize) as u32,
            k,
            self.params.profile.peer.allowed_fast_addr,
        );
        for index in set {
            if !peer_has(self, index) {
                self.allow_fast(index);
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
                if !self.sent_allowed_fast && self.metadata_known {
                    self.send_allowed_set();
                }
                events.push(Event::Interested);
            }
            Message::NotInterested => {
                self.peer_interested = false;
                events.push(Event::NotInterested);
            }
            Message::Have(i) => {
                self.check_index(i)?;
                let mut added = None;
                match &mut self.peer_have {
                    PeerHave::All => {}
                    PeerHave::Raw(_) => {} // cannot apply until metadata is known
                    _ => {
                        if let Some(b) = self.peer_pieces_mut()
                            && !b.get(i as usize)
                        {
                            b.set(i as usize);
                            added = Some(i);
                        }
                    }
                }
                events.push(Event::HaveChanged { added });
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
                events.push(Event::HaveChanged { added: None });
            }
            Message::HaveAll => {
                self.need_fast()?;
                self.peer_have = PeerHave::All;
                events.push(Event::HaveChanged { added: None });
            }
            Message::HaveNone => {
                self.need_fast()?;
                self.peer_have = match self.params.piece_count {
                    Some(n) => PeerHave::Pieces(Bitfield::new(n)),
                    None => PeerHave::Raw(Vec::new()),
                };
                events.push(Event::HaveChanged { added: None });
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
                    if ext.upload_only == Some(true) {
                        self.peer_upload_only = true;
                    }
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
            advertise_port: true,
            private: false,
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
        // The allowed-fast set waits for the peer's `interested` (libtorrent).
        assert_eq!(msgs.len(), 2);
        assert!(c.allowed_fast_granted().is_empty());
        c.receive(&Message::Interested.to_bytes()).unwrap();
        let msgs = decode_all(&c.take_outbound(), false);
        assert_eq!(msgs.len(), 5);
        assert!(msgs.iter().all(|m| matches!(m, Message::AllowedFast(_))));
        assert_eq!(c.allowed_fast_granted().len(), 5);
        // Once only.
        c.receive(&Message::Interested.to_bytes()).unwrap();
        assert!(c.take_outbound().is_empty());
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
        // No pieces and no fast extension: nothing to say (libtorrent skips
        // the empty bitfield).
        assert!(c.take_outbound().is_empty());
        // fast messages from a non-fast peer are violations
        assert!(c.receive(&Message::HaveAll.to_bytes()).is_err());
        // With pieces, a bitfield.
        let mut p = params(Role::Initiator, 12, false);
        p.our_have.set(3);
        let mut c = Connection::new(p);
        c.take_outbound();
        c.receive(&peer_hs(PLAIN)).unwrap();
        let msgs = decode_all(&c.take_outbound(), false);
        assert_eq!(msgs, vec![Message::Bitfield(vec![0x10, 0])]);
    }

    /// Allowed-fast skips pieces the peer has and covers every piece when
    /// the torrent is small (libtorrent `send_allowed_set`).
    #[test]
    fn allowed_fast_skips_peer_pieces_and_covers_small_torrents() {
        // 3 pieces < 5 grants: every piece the peer lacks, in index order.
        let mut c = Connection::new(params(Role::Responder, 3, true));
        c.receive(&peer_hs(FULL)).unwrap();
        c.take_outbound();
        c.receive(&Message::Bitfield(vec![0x40]).to_bytes())
            .unwrap(); // peer has piece 1
        c.receive(&Message::Interested.to_bytes()).unwrap();
        let msgs = decode_all(&c.take_outbound(), false);
        assert_eq!(msgs, vec![Message::AllowedFast(0), Message::AllowedFast(2)]);

        // 64 pieces: the canonical set minus what the peer has.
        let p = params(Role::Responder, 64, true);
        let set = crate::fast::allowed_fast_set(
            p.peer_ip.unwrap(),
            &p.info_hash,
            64,
            5,
            p.profile.peer.allowed_fast_addr,
        );
        let mut c = Connection::new(p);
        c.receive(&peer_hs(FULL)).unwrap();
        c.take_outbound();
        c.receive(&Message::Have(set[0]).to_bytes()).unwrap();
        c.receive(&Message::Interested.to_bytes()).unwrap();
        let msgs = decode_all(&c.take_outbound(), false);
        let expect: Vec<Message> = set[1..].iter().map(|&i| Message::AllowedFast(i)).collect();
        assert_eq!(msgs, expect);
    }

    /// Magnet mode: no have-state until `set_metadata`, which also sizes a
    /// bitfield the peer sent early.
    #[test]
    fn metadata_arrives_later() {
        let mut p = params(Role::Initiator, 16, false);
        p.piece_count = None;
        p.our_have = Bitfield::new(0);
        let mut c = Connection::new(p);
        c.take_outbound();
        c.receive(&peer_hs(FULL)).unwrap();
        let msgs = decode_all(&c.take_outbound(), false);
        assert_eq!(msgs.len(), 1, "only the LTEP handshake: {msgs:?}");
        assert!(!c.has_metadata());
        // Peer's bitfield is kept raw until we know the piece count.
        c.receive(&Message::Bitfield(vec![0xff, 0x00]).to_bytes())
            .unwrap();
        assert!(matches!(c.peer_have(), PeerHave::Raw(_)));
        c.receive(&Message::Interested.to_bytes()).unwrap();
        assert!(
            c.take_outbound().is_empty(),
            "no allowed-fast without metadata"
        );
        let mut have = Bitfield::new(16);
        have.set(9);
        let ev = c.set_metadata(16, have).unwrap();
        assert!(matches!(ev, Some(Event::HaveChanged { .. })));
        assert_eq!(c.peer_have().to_bitfield(16).count(), 8);
        let msgs = decode_all(&c.take_outbound(), false);
        assert_eq!(msgs[0], Message::Bitfield(vec![0x00, 0x40]));
        // The interested peer now gets its allowed-fast set (pieces it lacks).
        assert!(
            msgs[1..]
                .iter()
                .all(|m| matches!(m, Message::AllowedFast(i) if *i >= 8))
        );
        assert!(c.has_metadata());
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
        c.piece(r, vec![1; 16384]);
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
