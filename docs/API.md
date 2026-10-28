# PGStream API Reference (v0.2.0)

Semua native dideklarasikan di `pawn/include/pgstream.inc`. Versi plugin yang bisa dicek runtime: `PGSTREAM_VERSION` = `200`, string versi via `PG_Version`.

Format string umum (dipakai `PG_AsyncQuery` dan `PG_ExecutePrepared`):

| Kode | Arti | Argumen Pawn |
|---|---|---|
| `i` / `d` | integer 32-bit | `new` int |
| `f` | float | `Float:` |
| `s` | string | array char |
| `b` | boolean | `bool:` |
| `n` | NULL | (tidak ada argumen) |

Parameter query memakai placeholder PostgreSQL `$1, $2, ...` sesuai urutan kode format.

---

## PG_Version

```pawn
native PG_Version(dest[], size = sizeof(dest));
```

Mengisi `dest` dengan teks versi plugin (mis. `"PGStream 0.2.0"`) dan me-return kode versi integer (`200` untuk v0.2.0).

```pawn
new version[64];
new code = PG_Version(version, sizeof(version));
printf("PGStream %d ('%s')", code, version);
```

## PG_Connect

```pawn
native PG_Connect(const host[], const user[], const password[], const database[], port = 5432, const callback[] = "");
```

Koneksi dengan parameter individual (bentuk key-value). Perilaku TLS ditentukan oleh field `sslmode` di `pgstream.toml` (`[database]`, default `require`) — parameter TLS tidak bisa di-set per-panggilan:

- `sslmode=verify-ca` / `verify-full` — sertifikat diverifikasi (root store `webpki-roots` + hostname check).
- `sslmode=require` / `prefer` — terenkripsi **tanpa** verifikasi sertifikat (rawan MITM); plugin memlog warning sekali per koneksi. Produksi wajib `verify-full`.
- `sslmode=disable` — tanpa TLS.

Return connection handle (integer ≥ 0) atau `-1` saat gagal menyiapkan koneksi. Hasil koneksi sebenarnya dikirim ke `callback` (async):

- Callback signature: `forward <name>(connection, bool:success);`
- Pada `success=false`, ambi detail lewat `PG_GetError`.

```pawn
forward OnDBConnect(connection, bool:success);
g_conn = PG_Connect("127.0.0.1", "postgres", "secret", "samp_db", 5432, "OnDBConnect");
```

## PG_ConnectUrl

```pawn
native PG_ConnectUrl(const url[], const callback[] = "");
```

Koneksi lewat PostgreSQL URL. Semua mode `sslmode` didukung:

- `sslmode=disable` — tanpa TLS.
- `sslmode=prefer` — terenkripsi, **tanpa verifikasi sertifikat** (perilaku sama dengan `require` di PGStream).
- `sslmode=require` — terenkripsi, **tanpa verifikasi sertifikat** (rawan MITM; lihat README bagian TLS / sslmode).
- `sslmode=verify-ca` / `sslmode=verify-full` — sertifikat diverifikasi (root store `webpki-roots` + hostname check). Produksi wajib `verify-full`.

Jika `sslmode=` tidak ada atau kosong di URL, nilai `database.sslmode` di `pgstream.toml` (default `require`) dipakai sebagai fallback. Nilai yang tidak dikenal → koneksi ditolak (fail-closed).

Gunakan placeholder, contoh:

```pawn
forward OnDBConnect(connection, bool:success);

public OnGameModeInit()
{
    g_conn = PG_ConnectUrl(
        "postgresql://user:password@host:5432/dbname?sslmode=require&channel_binding=require",
        "OnDBConnect"
    );
    return 1;
}
```

Catatan error: jika URL tidak bisa diparse, koneksi gagal dan error dapat dibaca di callback via `PG_GetError`.

## PG_Close

```pawn
native PG_Close(connection);
```

Tutup koneksi handle dan bebaskan resource terkait. Setelah close, `PG_IsConnected` return `false`.

## PG_IsConnected

```pawn
native bool:PG_IsConnected(connection);
```

Return `true` jika koneksi handle masih hidup.

## PG_GetError

```pawn
native PG_GetError(connection, dest[], size = sizeof(dest));
```

Mengisi `dest` dengan pesan error terakhir untuk koneksi. Dipanggil dari callback ketika `success=false`, atau query error.

### Error umum

- **`Max connections reached (N)`** — `N` = `pool.max_size` di `pgstream.toml`. Terjadi saat jumlah koneksi aktif (`Connecting`/`Connected`) sudah mencapai batas; koneksi baru ditolak (callback koneksi terpanggil dengan `success=0`; error terbaca via `PG_GetError`). Catatan: `max_size` adalah batas koneksi hidup, bukan ukuran pool idle.
- **`Query timed out after Ns`** — `N` = `database.query_timeout_seconds`. Query melebihi timeout; callback query tetap terpanggil dengan `result` berisi error (teks error ada di `result.error` internal — belum ada native untuk membacanya; `PG_GetError` hanya menampilkan error level koneksi). Tetap panggil `PG_FreeResult(result)`.
- Koneksi yang melebihi `database.connect_timeout_seconds` gagal; detailnya terbaca via `PG_GetError` di callback koneksi.

## PG_EscapeString

```pawn
native PG_EscapeString(connection, const src[], dest[], size = sizeof(dest));
```

Escape string untuk injeksi literal SQL yang aman. Wajib punya koneksi valid (escape mengikuti server encoding).

```pawn
new raw[] = "O'Connor\\Admin; DROP TABLE users;--";
new esc[128];
PG_EscapeString(g_conn, raw, esc, sizeof(esc));
```

## PG_AsyncQuery

```pawn
native PG_AsyncQuery(connection, const query[], const callback[] = "", const format[] = "", {Float, _}:...);
```

Eksekusi query async, hasil ke callback:

- Callback signature: `forward <name>(connection, result, extra);`

`extra` menerima nilai yang di-set saat invoke pertama; untuk query varargs sederhana pass `""`. Query bisa parameterized lewat `$1, $2, ...` plus format varargs.

```pawn
forward OnTestQuery(connection, result, extra);
PG_AsyncQuery(g_conn, "SELECT 1+1 AS result", "OnTestQuery");

// Parameterized
forward OnTxInsert(connection, result, extra);
PG_AsyncQuery(g_conn,
    "INSERT INTO pgstream_test (name, score, active) VALUES ($1, $2, $3) RETURNING id, name, score",
    "OnTxInsert", "sib", "TestPlayer", 1337, 1
);
```

Catatan error: kalau query gagal SQL-nya, callback tetap terpanggil dengan `result` yang berisi error — teks error ada di `result.error` (internal); `PG_GetError` tidak menampilkan error level query. Selalu panggil `PG_FreeResult(result)` setelah selesai membaca.

## PG_Begin / PG_Commit / PG_Rollback

```pawn
native PG_Begin(connection, const callback[] = "");
native PG_Commit(connection, const callback[] = "");
native PG_Rollback(connection, const callback[] = "");
```

Transaksi async. Callback signature untuk ketiganya:

- `forward <name>(connection, bool:success);`

Gunakan pola: `Begin` → query-2 di tengah → `Commit` (atau `Rollback` saat gagal).

```pawn
forward OnTxBegin(connection, bool:success);
PG_Begin(g_conn, "OnTxBegin");
```

Sukses `Begin` ditandai `success=true` lalu query berikutnya masuk scope transaksi yang sama sampai `Commit`.

## PG_Listen

```pawn
native PG_Listen(connection, const channel[], const callback[] = "");
```

Subscribe ke channel PostgreSQL notify. Notifikasi yang masuk di-dispatch global ke:

- `forward OnPGNotify(connection, const channel[], const payload[]);`

Callback opsional (listened sukses/gagal):

- `forward <name>(connection, bool:success);`

```pawn
forward OnListenReady(connection, bool:success);
PG_Listen(g_conn, "pgstream_events", "OnListenReady");

public OnPGNotify(connection, const channel[], const payload[])
{
    printf("NOTIFY conn=%d channel='%s' payload='%s'", connection, channel, payload);
}
```

## PG_Notify

```pawn
native PG_Notify(connection, const channel[], const payload[] = "");
```

Kirim `NOTIFY channel, 'payload'` ke server. Penerima lain (termasuk sendiri di LISTEN yang sama) menerima lewat `OnPGNotify`.

## PG_Prepare

```pawn
native PG_Prepare(connection, const stmt_name[], const query[], const callback[] = "");
```

Simpan prepared statement dengan nama tantangan. Callback signature:

- `forward <name>(connection, bool:success);`

Pada gagal, `PG_GetError` memuat server error prepared statement.

```pawn
forward OnPrepared(connection, bool:success);
PG_Prepare(g_conn, "get_player", "SELECT id, name, score FROM pgstream_test WHERE score > $1 ORDER BY score DESC", "OnPrepared");
```

## PG_ExecutePrepared

```pawn
native PG_ExecutePrepared(connection, const stmt_name[], const callback[] = "", const format[] = "", {Float, _}:...);
```

Eksekusi prepared statement yang sudah di-`PG_Prepare`. Format varargs sama dengan `PG_AsyncQuery`. Callback signature:

- `forward <name>(connection, result, extra);` (sama dengan `OnQueryComplete`)

```pawn
forward OnPreparedQuery(connection, result, extra);
PG_ExecutePrepared(g_conn, "get_player", "OnPreparedQuery", "i", 100);
```

## Result API — by index

```pawn
native PG_NumRows(result);
native PG_NumFields(result);
native PG_GetAffectedRows(result);
native PG_GetString(result, row, col, dest[], size = sizeof(dest));
native PG_GetInt(result, row, col);
native Float:PG_GetFloat(result, row, col);
native bool:PG_IsNull(result, row, col);
native PG_FieldName(result, col, dest[], size = sizeof(dest));
```

- `row` 0-based; hasil kosong (`NumRows == 0`) tidak boleh diakses.
- `PG_GetAffectedRows` non-zero untuk DML (`INSERT/UPDATE/DELETE`); DDL umumnya 0.
- `PG_FieldName` mengambil nama kolom per index.
- Untuk `TIMESTAMP`, baca sebagai string (`PG_GetString`).

## Result API — by name

```pawn
native PG_GetStringByName(result, row, const col_name[], dest[], size = sizeof(dest));
native PG_GetIntByName(result, row, const col_name[]);
native Float:PG_GetFloatByName(result, row, const col_name[]);
native bool:PG_IsNullByName(result, row, const col_name[]);
```

Sama dengan versi index, tapi kolom disebut nama. Nama harus persis sama dengan alias/label kolom di query (pakai `AS` bila perlu).

```pawn
new name[32];
new score = PG_GetIntByName(result, 0, "score");
PG_GetStringByName(result, 0, "name", name, sizeof(name));
```

## PG_FreeResult

```pawn
native PG_FreeResult(result);
```

Wajib dipanggil setelah pemakaian result selesai, baik di callback sukses maupun gagal — result tidak di-free otomatis.
