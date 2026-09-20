# ADR 0005: Selective download, the parts file, and moving storage

- Status: accepted (2026-09-20)
- Relates to: AGENTS.md 4 (Tier 1: file priorities, move storage), 5.4; ADR 0004

## Context

File priorities are a Tier 1 feature: a caller must be able to skip files
without breaking piece-level integrity. Pieces do not align with files, so a
piece that straddles a skipped file and a wanted one must still be downloaded
and verified whole, and its skipped bytes must go *somewhere* without creating
the skipped file (users skip files precisely so they do not appear). Moving a
torrent's content while it runs is the other Tier 1 storage operation.
libtorrent solves both with a `part_file` and `move_storage`; we follow its
observable semantics without copying its code.

## Decision

1. **Priorities are per content file, `0..=7`, default 4** (libtorrent's
   scale). The public API numbers content files in torrent order; padding
   files (BEP 47) are internal and always 0. A piece's priority is the highest
   priority of the non-padding files it touches, so a straddling piece stays
   wanted. `TorrentStatus::total_wanted{,_done}` count wanted *files*.
2. **The parts file.** A skipped file that does not exist on disk is never
   created; the bytes of straddling pieces that fall into it are written to
   `<save_path>/.<name>.parts`, a sparse file indexed by torrent offset (so the
   mapping is trivial and the file's size is only the extents written). Reads
   for hashing and uploading go to the same place. A skipped file that already
   exists keeps receiving its bytes directly (libtorrent does the same). When a
   skipped file becomes wanted, the parts already held for it are exported
   into the real file, all over the ring.
3. **`completed` is for seeds.** A finished selective download fires
   `TorrentFinished` and turns the torrent upload-only (BEP 21), but the
   tracker sees `completed` only when every piece is present, and `left`
   keeps counting the skipped bytes: the announce stays truthful (rule 1) and
   matches libtorrent.
4. **Priorities persist in resume data** (format version 2; version 1 files
   read as "all default"; version 3, 0.2.0, adds `active_time` /
   `seeding_time` seconds and reads v1/v2 with zero times). The caller's `AddTorrent::file_priorities` win over
   the resume data's.
5. **Move storage quiesces, then renames.** `move_storage` raises a gate that
   disk reads/writes of that torrent wait on, waits for in-flight writes and
   hash checks to drain, then renames every file (copy-then-delete across
   filesystems, through the ring) and lowers the gate. Peers stay connected;
   their requests resume from the new location.

## Consequences

- `Storage` owns the priority state (`init_priorities`,
  `set_file_priorities`, `piece_priorities`, `file_done`, `move_to`); the
  engine maps content-file indices and drives the picker.
- Resume data trust considers only wanted files ("every file present"), since
  skipped files are legitimately absent.
- Tests: `crates/storage/tests/store.rs` (parts file, export, move),
  `crates/session/tests/files.rs` (API level), lab scenarios
  `file_priorities` and `move_storage` against the oracle seeder.
