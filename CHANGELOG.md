# CHANGELOG — PGStream

## [0.2.0] — 2026

Menurut `pawn/include/pgstream.inc` (PGSTREAM_VERSION = 200), `src/plugin.rs` (VERSION_TEXT "PGStream 0.2.0"), dan riwayat `src/`.

### Ditambahkan

- **TLS/SSL** pada connect: mode `sslmode=require`, `verify-ca`, `verify-full`
  - `verify-full`/`verify-ca` memakai root store terverifikasi (`webpki-roots`) — `src/plugin.rs::make_tls_connector_verified`
  - `require` (dan sslmode kosong) memakai no-validate verifier = encrypted nbytes tapi tanpa autentikasi (unauthenticated encryption, setara `sslmode=require` di libpq); by design, dokumentasi menyarankan `verify-full` untuk produksi
- **Koneksi via URL** — `PG_ConnectUrl(url, callback)`; TLS otomatis aktif jika `sslmode=` ada di URL
- **Transaksi** — `PG_Begin`, `PG_Commit`, `PG_Rollback` dengan callback `(connection, bool:success)`
- **LISTEN/NOTIFY** — `PG_Listen`, `PG_Notify`; notifikasi dispatch ke callback global `OnPGNotify(connection, channel, payload)`
- **Prepared statements** — `PG_Prepare`, `PG_ExecutePrepared`
- **Parameterized query varargs** — `PG_AsyncQuery(..., format, ...)` dengan kode `'i'/'d'` (int), `'f'` (float), `'s'` (string), `'b'` (bool), `'n'` (NULL), placeholder `$1..$n`
- **Timestamp extraction** — ekstraksi tipe timestamp via `chrono` (kolom `tokio-postgres` `with-chrono-0_4`)
- **Config plugin** `pgstream.toml` (`src/config.rs`): `[database]` (host/port/database/username/password, `password_env`, connect/query timeout), `[pool].max_size`, `[logging].level`

### Bugfix

- **AMX PushString slot 31** — panggilan PushString di table AMX SDK harus dilakukan via index 31; selain itu crash
- **Dereferensi varargs int** — pawncc 3.2.3664 (SA-MP) mengirim argumen `...` sebagai AMX address (by reference); format `'i'`/`'f'`/`'b'` kini di-dereference dengan benar, `'n'` = NULL
- **Bounds `native_arg` ke jumlah byte ABI varargs** — baca native varargs tidak lagi melebihi rentang argumen yang benar-benar dipush oleh Pawn

## [0.1.0] — M0 awal

- Plugin cdylib Rust → Windows x86 32-bit (`pgstream.dll`), cross-compile `i686-pc-windows-gnu` via `scripts/build-windows.sh`
- Koneksi individual (`PG_Connect`, tanpa TLS) dan tipe dasar `tokio-postgres`
- Async query (`PG_AsyncQuery`) di tokio runtime background, dispatch hasil ke Pawn lewat `ProcessTick()`
- Result API by index: `PG_NumRows`, `PG_NumFields`, `PG_GetAffectedRows`, `PG_GetString`, `PG_GetInt`, `PG_GetFloat`, `PG_IsNull`, `PG_FieldName`
- `PG_Close`, `PG_IsConnected`, `PG_GetError`, `PG_EscapeString`, `PG_FreeResult`
- Registry handle: `CONNECTIONS`, `RESULTS` (`src/handles.rs`)
