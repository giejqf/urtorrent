# Resume data

How a torrent's state survives a restart, and how it compares with
libtorrent's `write_resume_data_buf()` / `read_resume_data()`.

## Two ways to keep it

- **Engine-managed files**: `AddTorrent::resume_dir(dir)` makes the engine
  read `<infohash>.resume` at add time and write it periodically while the
  torrent changes, on `save_resume_data`, and on shutdown. Writes are
  atomic (tmp + fsync + rename + directory fsync).
- **Caller-managed blobs** (libtorrent's model): `Session::resume_data(id)`
  returns the same data as bytes; the caller stores them (a database, its
  own files) and passes them back through `AddTorrent::resume_data(bytes)`.
  `TorrentStatus::needs_resume_save` (libtorrent `need_save_resume`) says
  when a fresh blob is worth fetching; fetching clears it. A blob given at
  add time wins over a `resume_dir` file. The info-hash inside must match
  the torrent being added, or the blob is ignored.

Either way the data is only written after the torrent's files are
`fsync`ed, so everything it claims is on disk: `kill -9` at any moment never
yields a torrent that claims pieces it does not have (AGENTS.md 5.4). If the
data does not match the metainfo, the disk is rechecked instead. If it
vouches for content (verified pieces or written ranges) and a wanted file is
gone, the torrent stops with `ErrorKind::ContentMissing` and creates nothing
(libtorrent rejects such a fast resume; qBittorrent shows "missing files",
docs/quirks.md Q28). The data is kept and saved back as it was:
`Session::resume` tries it again once the files are back, and
`Session::force_recheck` accepts what the disk holds instead.

## What the blob holds (format 6)

Bencoded dictionary, `format` = 6; every version reads every older version
(format 1 → 6 are all accepted; fields absent in an older file take their
defaults).

| Key | Meaning |
|---|---|
| `info_hash`, `piece_length`, `total_length`, `pieces` | identity and sanity checks against the metainfo |
| `have` | verified pieces (bitfield) |
| `unfinished` | pieces in progress: `[piece, start, end, start, end, ...]` byte ranges written and synced but not yet hashed. Restored as downloaded blocks (whole 16 KiB blocks inside a range), read back from disk by the hash cursor; a piece whose blocks are all there is hashed at once, and a failed hash discards it and blames the disk alongside the peers |
| `uploaded`, `downloaded`, `active_time`, `seeding_time` | counters (truthful; never edited) |
| `added_time`, `completed_time` | unix seconds |
| `file_priorities`, `mapped_files` | selection and renames (v2, v5) |
| `sequential`, `upload_limit`, `download_limit`, `max_peers`, `max_uploads` | per-torrent settings (v5); `AddTorrent`'s explicit values win |
| `auto_managed`, `queue_position` | queue standing (v4) |
| `trackers`, `web_seeds` | the lists as they stood (v6); they replace the metainfo's on load, like libtorrent's resume trackers, so trackers added or removed at runtime persist |
| `peers`, `peers6` | up to 100 addresses to dial first (compact form; connected peers by their listen address, then the freshest candidates); they come back as `PeerSource::Resume` |

Not in the blob, on purpose: the metainfo (`Session::torrent_file`
returns it; libtorrent optionally embeds it), the save path and whether
the torrent is paused (the caller decides both on every add), anything
frontend-side (categories, tags).

## Versus libtorrent

| | libtorrent | urtorrent |
|---|---|---|
| Blob | bencoded `add_torrent_params` (`file-format: libtorrent resume file`) | bencoded, own format, versioned; not interoperable |
| Who stores it | the client (`save_resume_data_alert` → `write_resume_data_buf`) | either the engine (`resume_dir`) or the client (`resume_data` / `AddTorrent::resume_data`) |
| When to save | poll `need_save_resume_data()` | `TorrentStatus::needs_resume_save`, plus periodic and shutdown saves in `resume_dir` mode |
| Unfinished pieces | block bitmaps, trusted until the piece's hash | written byte ranges, same trust model (hashed when the piece completes; the prefix is hashed at restore) |
| Verified pieces | trusted if files' mtimes/sizes match | trusted if the wanted files exist and the metainfo matches; the check is the fallback |
| Trackers | resume trackers replace (or merge with a flag) | replace |
| Peers | up to `max_resume_peers` | up to 100 |
| Metainfo inside | optional (`save_info_dict`) | never; `torrent_file(id)` |
| Paused / save path | in the blob | the caller's, on every add |
