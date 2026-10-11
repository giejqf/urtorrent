# Resume data

How a torrent's state survives a restart, and how this compares with
libtorrent's `write_resume_data_buf()` / `read_resume_data()`.

## Two ways to keep it

- **Engine-managed files**: `AddTorrent::resume_dir(dir)` makes the engine
  read `<infohash>.resume` from `dir` when the torrent is added, and write
  it periodically while the torrent changes, on `save_resume_data`, and on
  shutdown. Writes are atomic: temp file, `fsync`, rename, directory
  `fsync`.
- **Caller-managed blobs** (libtorrent's model): `Session::resume_data(id)`
  returns the same data as bytes. The caller stores them (a database, its
  own files) and passes them back through `AddTorrent::resume_data(bytes)`.
  A blob given at add time is used instead of a `resume_dir` file. Its
  info-hash must match the torrent being added, or it is ignored.

`TorrentStatus::needs_resume_save` (libtorrent's `need_save_resume`) says
when a fresh blob is worth fetching; fetching one clears it. Any change to
a field the blob records sets it, including a queue move, which marks every
torrent it shifts. The exceptions are the transfer counters and activity
times: they change all the time and ride along with the next save.

## What the data guarantees

Resume data is written only after the torrent's files are `fsync`ed, so
everything it claims is on disk: `kill -9` at any moment never yields a
torrent that claims pieces it does not have (AGENTS.md 5.4).

- If the data does not match the metainfo, the content is rechecked
  instead.
- If the data vouches for content (verified pieces or written ranges) and a
  wanted file is gone, the torrent stops with `ErrorKind::ContentMissing`
  and creates nothing. This matches libtorrent rejecting such a fast resume
  and qBittorrent showing "missing files" (docs/quirks.md Q28). The data is
  kept and saved back unchanged: `Session::resume` tries it again once the
  files are back, and `Session::force_recheck` accepts what the disk holds
  instead.

## What the blob holds (format 8)

A bencoded dictionary with `format` = 8. A build reads every format up to
its own, so 1 to 8 are all accepted; fields missing from an older file take
their defaults. A newer format is rejected.

| Key | Meaning |
|---|---|
| `info_hash`, `piece_length`, `total_length`, `pieces` | identity, and sanity checks against the metainfo |
| `have` | verified pieces (bitfield) |
| `unfinished` | pieces in progress (v6, at most 4096): a list of `[piece, start, end, start, end, ...]`, the byte ranges written and synced but not yet hashed. They come back as downloaded blocks (whole 16 KiB blocks inside a range) that the hash cursor reads back from disk. A piece whose blocks are all there is hashed at once; if it fails, it is discarded and the disk is blamed alongside the peers |
| `uploaded`, `downloaded` | transfer counters (truthful; never edited) |
| `active_time`, `seeding_time` | seconds active and seconds seeding (v3) |
| `added_time`, `completed_time` | unix seconds (v6) |
| `last_seen_complete`, `last_download`, `last_upload` | unix seconds (v7): when a complete copy (a connected seed, or ours) was last seen, and when payload last arrived and left, as libtorrent keeps them |
| `file_priorities` | file selection (v2) |
| `mapped_files` | renamed file paths (v5) |
| `piece_priorities` | one byte per piece (v8), only when set with `set_piece_priorities`; ignored when the caller gives file priorities on add |
| `sequential`, `upload_limit`, `download_limit`, `max_peers`, `max_uploads` | per-torrent settings (v5); values given explicitly in `AddTorrent` win |
| `auto_managed`, `queue_position` | queue standing (v4) |
| `trackers`, `web_seeds` | the lists as they stood (v6). On load a non-empty list replaces the metainfo's, like libtorrent's resume trackers, so trackers added or removed at runtime persist. An empty list means "use the metainfo's": removing every tracker or web seed does not survive a restart |
| `peers`, `peers6` | up to 100 addresses to dial first (v6, compact form): connected peers by their listen address, then the freshest candidates. They come back as `PeerSource::Resume` |

Left out on purpose:

- the metainfo: `Session::torrent_file` returns it (libtorrent can embed
  it);
- the save path and whether the torrent is paused or held: the caller
  decides on every add;
- frontend-side state such as categories and tags.

## Versus libtorrent

| | libtorrent | urtorrent |
|---|---|---|
| Blob | bencoded `add_torrent_params` (`file-format: libtorrent resume file`) | bencoded, own versioned format; not interoperable |
| Who stores it | the client (`save_resume_data_alert` → `write_resume_data_buf`) | the engine (`resume_dir`) or the client (`resume_data` / `AddTorrent::resume_data`) |
| When to save | poll `need_save_resume_data()` | `TorrentStatus::needs_resume_save`, plus periodic and shutdown saves in `resume_dir` mode |
| Unfinished pieces | block bitmaps, trusted until the piece's hash | written byte ranges, same trust model: hashed when the piece completes, the contiguous prefix hashed at restore |
| Verified pieces | trusted if the files' mtimes and sizes match | trusted if the wanted files exist and the metainfo matches; a check is the fallback |
| Files gone | fast resume rejected, torrent errored ("missing files") | `ErrorKind::ContentMissing` with the data kept; `resume` looks again, `force_recheck` starts over |
| Trackers | resume trackers replace the metainfo's (or merge, with a flag) | replace |
| Peers | up to `max_resume_peers` | up to 100 |
| Metainfo inside | optional (`save_info_dict`) | never; `torrent_file(id)` |
| Paused / save path | in the blob | the caller's, on every add |
