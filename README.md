# PGStream

Plugin PostgreSQL native untuk SA:MP, ditulis dalam Rust. **Versi 0.2.1** (patch hardening di atas 0.2.0; v0.1.0 awal, M0).

- Target: Windows x86 32-bit (`cdylib`), output `pgstream.dll` (PE32).
- Koneksi via `tokio-postgres` + `rustls` — tanpa dependensi libpq.
- Runtime async tokio di background; dispatch hasil ke Pawn lewat `ProcessTick()`.
-pawncc yang dipakai: 3.2.3664 (pawncc SA-MP). Lihat [Catatan ABI varargs](#catatan-abi-varargs-pawncc-323664).

## Daftar Isi

1. [Fitur](#fitur)
2. [Native API](#native-api)
3. [Build](#build)
4. [Deploy ke server SA:MP](#deploy-ke-server-samp)
5. [Konfigurasi pgstream.toml](#konfigurasi-pgstreamtoml)
6. [Kompilasi Pawn](#kompilasi-pawn)
7. [Catatan ABI varargs (pawncc 3.2.3664)](#catatan-abi-varargs-pawncc-323664)
8. [Arsitektur](#arsitektur)
9. [Testing](#testing)
10. [CI & Release](#ci--release)
11. [Batasan yang diketahui](#batasan-yang-diketahui)
12. [Verified against](#verified-against)

## Fitur

- **Zero-dependency**: tidak butuh libpq; protokol PostgreSQL murni Rust (`tokio-postgres`, `rustls`).
- **Asynchronous**: query jalan di tokio runtime background; game loop tidak pernah blocking.
- **TLS/SSL** di kedua jalur koneksi: `PG_ConnectUrl` (parameter `sslmode=` di URL) dan `PG_Connect` (field `sslmode` di `pgstream.toml`, default `require`). Mode: `disable`, `prefer`, `require`, `verify-ca`, `verify-full`. Teruji dari `pawn/tests/pgstream_test.pwn` ke Neon managed Postgres. Lihat [TLS / sslmode](#tls--sslmode) — produksi wajib `verify-full`.
- **Transaksi**: `PG_Begin` / `PG_Commit` / `PG_Rollback`.
- **LISTEN/NOTIFY**: pub/sub antipoll — `PG_Listen` / `PG_Notify`, callback global `OnPGNotify`.
- **Prepared statements**: `PG_Prepare` / `PG_ExecutePrepared`.
- **Parameterized queries**: placeholder `$1, $2, ...` + format string `'is f b'` (tal, float, string, bool, null) via varargs.
- **Batas koneksi aktif** — `pool.max_size` membatasi jumlah koneksi hidup (`Connecting`/`Connected`), bukan pool idle; koneksi di atas batas ditolak dengan error `Max connections reached (N)`.
- **Result API** dua arah: index kolom dan nama kolom.

## Native API

Ringkasan; spesifikasi lengkap per native lihat [docs/API.md](docs/API.md).

| Native | Fungsi |
|---|---|
| `PG_Version(dest[], size)` | Kode & teks versi plugin |
| `PG_Connect(host,user,pass,db,port,cb)` | Koneksi key-value; TLS sesuai `sslmode` di `pgstream.toml` (default `require`) |
| `PG_ConnectUrl(url,cb)` | Koneksi via URL; TLS sesuai `sslmode=` di URL (fallback: config) |
| `PG_Close(conn)` | Tutup koneksi |
| `PG_IsConnected(conn)` | Status hidup koneksi |
| `PG_GetError(conn,dest,size)` | Pesan error terakhir |
| `PG_EscapeString(conn,src,dest,size)` | Escape string untuk SQL |
| `PG_AsyncQuery(conn,query,cb,format,...)` | Query async + parameter varargs |
| `PG_Begin/PG_Commit/PG_Rollback(conn,cb)` | Transaksi |
| `PG_Listen(conn,channel,cb)` / `PG_Notify(conn,channel,payload)` | Pub/sub |
| `PG_Prepare(conn,name,query,cb)` / `PG_ExecutePrepared(conn,name,cb,format,...)` | Prepared statement |
| `PG_NumRows/PG_NumFields/PG_GetAffectedRows(result)` | Info result |
| `PG_GetString/PG_GetInt/PG_GetFloat/PG_IsNull(result,row,col,...)` / `..._ByName` | Baca cell, by index atau nama kolom |
| `PG_FieldName(result,col,dest,size)` | Nama kolom |
| `PG_FreeResult(result)` | Bebaskan memori result |

Semua native dideklarasikan di `pawn/include/pgstream.inc` (`PGSTREAM_VERSION` = 200).

## Build

Cross-compile dari Linux ke Windows i686 (MinGW toolchain harus terinstal, target `rustup target add i686-pc-windows-gnu`):

```sh
./scripts/build-windows.sh
```

Output: `target/i686-pc-windows-gnu/release/pgstream.dll`. Script memverifikasi DLL adalah PE32 (32-bit) — build gagal kalau tidak.

Kalau mau build langsung dengan cargo:

```sh
cargo build --target i686-pc-windows-gnu --release
```

## Deploy ke server SA:MP

1. Salin `pgstream.dll` ke folder `plugins/` server SA:MP.
2. Di `server.cfg` tambahkan:
   ```
   plugins pgstream.dll
   ```
3. Letakkan `pgstream.toml` di folder root server SA:MP (selevel `server.cfg`). Contoh minimal:

   ```toml
   [database]
   host = "127.0.0.1"
   port = 5432
   database = "novalife_db"
   username = "postgres"
   password_env = "PGSTREAM_DB_PASSWORD"
   sslmode = "verify-full"
   connect_timeout_seconds = 5
   query_timeout_seconds = 10

   [pool]
   max_size = 10

   [logging]
   level = "debug"
   ```

   Field lengkap lihat bagian [Konfigurasi](#konfigurasi-pgstreamtoml). Contoh memakai `password_env` (password dari env var, bukan plaintext di file) dan `sslmode = "verify-full"` (wajib produksi); `pool.max_size` = batas koneksi aktif, bukan pool idle.
4. Restart server. Plugin load saat `Load()` SA:MP SDK; versi tercetak lewat `logprintf`.

## Konfigurasi pgstream.toml

Struct sumber `src/config.rs`. Semua section punya default; field wajib dalam praktiknya: `host`, `port`, `database`, `username`.

`[database]`:

| Field | Tipe | Default | Keterangan |
|---|---|---|---|
| `host` | string | `127.0.0.1` | Host database |
| `port` | u16 | 5432 | Port PostgreSQL |
| `database` | string | `samp_db` | Nama database |
| `username` | string | `postgres` | User database |
| `password` | string | `""` | Password |
| `password_env` | string (ops.) | — | Nama env var; jika ada dan env var terbaca, menimpa `password` |
| `sslmode` | string | `require` | Mode TLS; lihat [TLS / sslmode](#tls--sslmode) |
| `connect_timeout_seconds` | u64 | 5 | Batas durasi koneksi (diterapkan) |
| `query_timeout_seconds` | u64 | 15 | Batas durasi query (diterapkan); melebihi → error `Query timed out after Ns` |

`[pool]`:

| Field | Default | Keterangan |
|---|---|---|
| `max_size` | 5 | Batas jumlah koneksi aktif (`Connecting`/`Connected`), bukan pool idle; koneksi di atas batas ditolak dengan error `Max connections reached (N)` |

### TLS / sslmode

Perilaku TLS per mode (berlaku di kedua jalur koneksi — `PG_Connect` via field `sslmode` di `pgstream.toml`, `PG_ConnectUrl` via parameter URL):

| Mode | TLS | Verifikasi sertifikat | Catatan |
|---|---|---|---|
| `disable` | tidak | — | Koneksi plaintext. Hanya untuk lokal/LAN tepercaya. |
| `prefer` | ya | tidak | Terenkripsi, **tanpa** verifikasi. Sama dengan `require` di PGStream. |
| `require` | ya | tidak | Terenkripsi **tanpa** verifikasi sertifikat. **Rawan MITM.** Default kalau config tidak punya key. |
| `verify-ca` | ya | ya (webpki-roots + hostname) | |
| `verify-full` | ya | ya (webpki-roots + hostname) | **Wajib untuk produksi.** |

> **Peringatan**: `require`/`prefer` mengenkripsi traffic tapi **tidak memverifikasi identitas server yang kamu hubungkan** — penyerang di jalur (MITM) bisa menyajikan sertifikat apa pun. By-design (`setara require` di libpq), tapi **produksi wajib `sslmode=verify-full`**. Saat mode terenkripsi-tanpa-verifikasi aktif, plugin mencetak warning sekali per koneksi: `[PGStream] WARN: TLS tanpa verifikasi sertifikat (sslmode=...)`.

Catatan implementasi: `verify-ca` dan `verify-full` memakai connector terverifikasi yang sama (root store `webpki-roots`, cek hostname; TLS 1.2/1.3). Code tidak membedakan keduanya. Nilai `sslmode` yang tidak dikenal dibiarkan (koneksi ditolak / fail-closed). `sslmode` kosong atau tidak ada → fallback ke `database.sslmode` (default `require`).

`[logging]`:

| Field | Default | Keterangan |
|---|---|---|
| `level` | `info` | `debug` untuk troubleshooting |

Catatan: kalau file tidak ada / TOML tidak valid, `Config::load_from_file` diam-diam fallback ke struct Default (jangan berharap error log dari konfigurasi).

## Kompilasi Pawn

Include: `pawn/include/pgstream.inc`. Contoh pemakaian: `pawn/tests/pgstream_test.pwn`.

Dua opsi compiler:

```sh
# Wine (Linux)
wine pawno/pawncc pawn/tests/pgstream_test.pwn -i pawn/include -o gamemodes/pgstream_test.amx

# Native (Windows / pawncc SA-MP)
pawncc pgstream_test.pwn -i+/include -o gamemodes\pgstream_test
```

Gunakan pawncc **3.2.3664** (dirilis bersama SA-MP). Compiler Pawn alternatif (Pawn 4 / openmp) punya ABI varargs berbeda — lihat di bawah.

## Catatan ABI varargs (pawncc 3.2.3664)

pawncc 3.2.3664 (SA-MP) push argumen `...` variadic ke AMX sebagai **AMX address (by reference)**, bukan nilai langsung:

- format `'i'`/`'d'` (int) dan `'f'` (float) dan `'b'` (bool): file asam men-dereference alamat cell untuk ambil nilai.
- format `'n'` = null: tidak di-dereference (parameter NULL di query).
- format `'s'` (string): alamat string AMX, dibaca rentang hingga terminator.

Bugfix terkait (v0.2.0):

- PushString di AMX SDK table harus dipanggil lewat **slot 31** (`src/abi/amx.rs`: `PUSH_STRING = 31`). Salah slot menyebabkan crash.
- Argumen `native_arg` dibounds ke **jumlah byte ABI varargs** — lebih dari itu menambatkan data kotor.

Konsekuensi praktis untuk pemilik gamemode:

- Jangan panggil `PG_AsyncQuery`/`PG_ExecutePrepared` dari compiler selain pawncc 3.2.3664.
- Selalu isi `format` dan argumen secara berpasangan; format `'n'` tidak butuh argumen di daftar varargs.
- Ukuran array tujuan (`dest[]`) dihitung dengan `sizeof(dest)` agar tidak overread.

## Arsitektur

Plugin adalah cdylib (`crate-type = ["cdylib", "rlib"]`) yang diekspor melalui SDK SA:MP (`Supports`, `Load`, `Unload`, `ProcessTick`, amx_functions table). Di `Load()` plugin register semua native lewat AMX callback registration (tabel SDK index 80 dst, `PushString` = 31) dan menyimpan pointer ke `logprintf` untuk output server console.

Tiap koneksi (management oleh `handles.rs`: `CONNECTIONS`, `RESULTS`) menjalankan command di tokio runtime multi-thread background. Hasil (rows, error, event `LISTEN`, penyelesaian query/transaksi) dikembalikan sebagai event ke queue (`CompletionEvent`); `ProcessTick()` dari main thread SA:MP mem-fetch events tiap tick dan menjalankan publik Pawn callback (`OnQueryComplete(connection, result, extra)` dsb) — jadi tidak ada thread Pawn yang dieksekusi di luar main thread.

## Testing

- Unit/integration Rust: `cargo test`.
- Live test end-to-end: `pawn/tests/pgstream_test.pwn` — mencakup TLS connect, SELECT/INSERT, transaksi, prepared statement, LISTEN/NOTIFY, escape string. Jalankan sebagai gamemode di server SA:MP dengan `pgstream.toml` mengarah ke database test.
- E2E harness: `scripts/test-e2e.sh <server-dir> [timeout-detik]` — build `pgstream.dll`, salin ke `server-dir/plugins/pgstream.dll`, kompilasi `pawn/tests/pgstream_test.pwn` → `.amx` via wine `pawncc.exe` (`pawno/include` + `pawn/include`), jalankan `samp-server.exe` (wine) dan asersi log (`PASS: ...`, tanpa `FAIL`). URL database test dari env **`PGSTREAM_TEST_URL`** (sekret tidak disimpan di repo; disuntikkan ke salinan `.pwn` via `sed`). Jika `PGSTREAM_TEST_URL` kosong/tidak di-set → print `SKIP` & exit 0.

## CI & Release

- **CI** (`.github/workflows/ci.yml`, jalan di setiap push/PR): `cargo fmt --check`, clippy, `cargo test` (host), cross-build `pgstream.dll` (`i686-pc-windows-gnu`, PE32 x86), upload artifact.
- **Release otomatis** (`.github/workflows/release.yml`): push tag `v*` → GitHub release berisi `pgstream.dll` + `pawn/include/pgstream.inc`; release notes diambil dari section teratas `CHANGELOG.md`. Tag ulang release yang sama meng-overwrite file (`--clobber`).

## Batasan yang diketahui

- Tipe kolom belum didukung: `NUMERIC`, `UUID`, `JSON`/`JSONB`, `BYTEA`. Baca via `PG_GetString` tidak dijamin.
- **`sslmode=require`/`prefer` tidak memverifikasi sertifikat server** (encrypted tapi unauthenticated — setara `require` di libpq). Berlaku untuk kedua jalur koneksi (`PG_Connect` via config, `PG_ConnectUrl` via URL). By design; **produksi wajib `sslmode=verify-full`** (lihat [TLS / sslmode](#tls--sslmode)).
- Format varargs terikat ke **pawncc 3.2.3664**. Compiler Pawn lain tak kompatibel.
- `PG_EscapeString` pada koneksi yang belum connect (`conn=0`) didokumentasi di test bergantung pada koneksi pertama; holder harus punya koneksi valid.

## Verified against

| Komponen | Versi |
|---|---|
| SA:MP | 0.3.7-R2 |
| PostgreSQL | 18.6 (Neon) |
| pawncc | 3.2.3664 |
