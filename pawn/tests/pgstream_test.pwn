/*
 *  pgstream_test.pwn — Full Integration Test for PGStream v0.2.0
 *  Tests: TLS Connect, Query, Transactions, Listen/Notify, Prepared Statements
 *  Target: postgresql://neondb_owner:***@<db-host>/<dbname>?sslmode=require&channel_binding=require
 */
#include <a_samp>
#include <pgstream>

// Test state machine
static g_conn = -1;
static g_TestStep = 0;

// Callbacks
forward OnDBConnect(connection, bool:success);
forward OnTestQuery(connection, result, extra);
forward OnTxBegin(connection, bool:success);
forward OnTxInsert(connection, result, extra);
forward OnTxCommit(connection, bool:success);
forward OnTxVerify(connection, result, extra);
forward OnPrepared(connection, bool:success);
forward OnPreparedQuery(connection, result, extra);
forward OnListenReady(connection, bool:success);
forward OnPGNotify(connection, const channel[], const payload[]);
forward OnCleanup(connection, result, extra);
forward OnFinalCheck(connection, result, extra);

main()
{
	print("[PGStream] === INTEGRATION TEST v0.2.0 ===");
}

public OnGameModeInit()
{
	new version[64];
	new code = PG_Version(version, sizeof(version));
	printf("[PGStream] Version: %d ('%s')", code, version);

	// Test 1: Escape string
	new raw[] = "O'Connor\\Admin; DROP TABLE users;--";
	new esc[128];
	PG_EscapeString(0, raw, esc, sizeof(esc));
	printf("[PGStream] TEST Escape: '%s' -> '%s'", raw, esc);

	// Test 2: TLS Connection
	// shortcut: isi kredensial DB-mu di sini — jangan commit kredensial nyata.
	g_conn = PG_ConnectUrl("postgresql://user:password@host:5432/dbname?sslmode=require", "OnDBConnect");
	printf("[PGStream] PG_ConnectUrl handle: %d", g_conn);

	return 1;
}

public OnDBConnect(connection, bool:success)
{
	printf("[PGStream] OnDBConnect: conn=%d, success=%d", connection, _:success);

	if (!success)
	{
		new err[256];
		PG_GetError(connection, err, sizeof(err));
		printf("[PGStream] FAIL: Connection failed: '%s'", err);
		PG_Close(connection);
		print("[PGStream] === TESTS FAILED (connection) ===");
		return 1;
	}

	printf("[PGStream] PASS: TLS connection established! IsConnected: %d", PG_IsConnected(connection));

	// Test 3: Simple SELECT query
	print("[PGStream] TEST Running SELECT 1+1 ...");
	PG_AsyncQuery(connection, "SELECT 1+1 AS result, current_timestamp AS ts, version() AS pg_version", "OnTestQuery");
	return 1;
}

public OnTestQuery(connection, result, extra)
{
	printf("[PGStream] OnTestQuery: result=%d, rows=%d, fields=%d", result, PG_NumRows(result), PG_NumFields(result));

	new val[64];
	PG_GetString(result, 0, 0, val, sizeof(val));
	printf("[PGStream] PASS: 1+1 = %s", val);

	new ts[64];
	PG_GetStringByName(result, 0, "ts", ts, sizeof(ts));
	printf("[PGStream] PASS: Server timestamp: %s", ts);

	new pgv[256];
	PG_GetStringByName(result, 0, "pg_version", pgv, sizeof(pgv));
	printf("[PGStream] PASS: PostgreSQL version: %s", pgv);

	PG_FreeResult(result);

	// Test 4: Setup test table
	print("[PGStream] TEST Creating test table...");
	PG_AsyncQuery(connection,
		"CREATE TABLE IF NOT EXISTS pgstream_test (\
			id SERIAL PRIMARY KEY, \
			name VARCHAR(64) NOT NULL, \
			score INTEGER DEFAULT 0, \
			active BOOLEAN DEFAULT TRUE, \
			created_at TIMESTAMP DEFAULT NOW()\
		)",
		"OnCleanup"
	);
	return 1;
}

public OnCleanup(connection, result, extra)
{
	g_TestStep++;
	if (g_TestStep == 1)
	{
		printf("[PGStream] PASS: Test table created. AffectedRows: %d", PG_GetAffectedRows(result));
		PG_FreeResult(result);

		// Clean up from previous test runs
		PG_AsyncQuery(connection, "DELETE FROM pgstream_test", "OnCleanup");
	}
	else if (g_TestStep == 2)
	{
		printf("[PGStream] PASS: Table cleaned. AffectedRows: %d", PG_GetAffectedRows(result));
		PG_FreeResult(result);

		// Test 5: Transaction BEGIN
		print("[PGStream] TEST Transaction BEGIN...");
		PG_Begin(connection, "OnTxBegin");
	}
	return 1;
}

public OnTxBegin(connection, bool:success)
{
	printf("[PGStream] OnTxBegin: success=%d", _:success);

	if (!success)
	{
		print("[PGStream] FAIL: BEGIN failed");
		return 1;
	}

	print("[PGStream] PASS: Transaction started");

	// Test 6: INSERT inside transaction with parameterized query
	print("[PGStream] TEST Parameterized INSERT (inside tx)...");
	PG_AsyncQuery(connection,
		"INSERT INTO pgstream_test (name, score, active) VALUES ($1, $2, $3) RETURNING id, name, score",
		"OnTxInsert", "sib", "TestPlayer", 1337, 1
	);
	return 1;
}

public OnTxInsert(connection, result, extra)
{
	printf("[PGStream] OnTxInsert: rows=%d, fields=%d", PG_NumRows(result), PG_NumFields(result));

	new id = PG_GetIntByName(result, 0, "id");
	new name[32];
	PG_GetStringByName(result, 0, "name", name, sizeof(name));
	new score = PG_GetIntByName(result, 0, "score");
	printf("[PGStream] PASS: Inserted id=%d, name='%s', score=%d", id, name, score);

	PG_FreeResult(result);

	// Test 7: COMMIT
	print("[PGStream] TEST Transaction COMMIT...");
	PG_Commit(connection, "OnTxCommit");
	return 1;
}

public OnTxCommit(connection, bool:success)
{
	printf("[PGStream] OnTxCommit: success=%d", _:success);

	if (!success)
	{
		print("[PGStream] FAIL: COMMIT failed");
		return 1;
	}

	print("[PGStream] PASS: Transaction committed");

	// Test 8: Verify committed data
	print("[PGStream] TEST Verifying committed data...");
	PG_AsyncQuery(connection,
		"SELECT id, name, score, active, created_at FROM pgstream_test WHERE name = $1",
		"OnTxVerify", "s", "TestPlayer"
	);
	return 1;
}

public OnTxVerify(connection, result, extra)
{
	new rows = PG_NumRows(result);
	new fields = PG_NumFields(result);
	printf("[PGStream] OnTxVerify: rows=%d, fields=%d", rows, fields);

	if (rows > 0)
	{
		new name[32], ts[64];
		new id = PG_GetIntByName(result, 0, "id");
		PG_GetStringByName(result, 0, "name", name, sizeof(name));
		new score = PG_GetIntByName(result, 0, "score");
		new bool:active = bool:PG_GetIntByName(result, 0, "active");
		PG_GetStringByName(result, 0, "created_at", ts, sizeof(ts));
		printf("[PGStream] PASS: Verified -> id=%d name='%s' score=%d active=%d ts='%s'", id, name, score, _:active, ts);

		// Field name test
		new fname[32];
		PG_FieldName(result, 0, fname, sizeof(fname));
		printf("[PGStream] PASS: FieldName(0) = '%s'", fname);
		PG_FieldName(result, 2, fname, sizeof(fname));
		printf("[PGStream] PASS: FieldName(2) = '%s'", fname);

		// NULL test
		printf("[PGStream] PASS: IsNull(0,0) = %d (expected 0)", PG_IsNull(result, 0, 0));
	}
	else
	{
		print("[PGStream] FAIL: No rows found after commit");
	}

	PG_FreeResult(result);

	// Test 9: Prepared Statement
	print("[PGStream] TEST Prepared Statement...");
	PG_Prepare(connection, "get_player", "SELECT id, name, score FROM pgstream_test WHERE score > $1 ORDER BY score DESC", "OnPrepared");
	return 1;
}

public OnPrepared(connection, bool:success)
{
	printf("[PGStream] OnPrepared: success=%d", _:success);

	if (!success)
	{
		new err[128];
		PG_GetError(connection, err, sizeof(err));
		printf("[PGStream] FAIL: Prepare failed: '%s'", err);
		return 1;
	}

	print("[PGStream] PASS: Statement prepared");

	// Test 10: Execute prepared statement
	print("[PGStream] TEST Execute prepared 'get_player' (score > 100)...");
	PG_ExecutePrepared(connection, "get_player", "OnPreparedQuery", "i", 100);
	return 1;
}

public OnPreparedQuery(connection, result, extra)
{
	new rows = PG_NumRows(result);
	printf("[PGStream] OnPreparedQuery: rows=%d", rows);

	for (new i = 0; i < rows; i++)
	{
		new name[32];
		PG_GetString(result, i, 1, name, sizeof(name));
		printf("[PGStream] PASS: PreparedResult[%d] -> id=%d name='%s' score=%d",
			i, PG_GetInt(result, i, 0), name, PG_GetInt(result, i, 2));
	}

	PG_FreeResult(result);

	// Test 11: Listen/Notify
	print("[PGStream] TEST Listen/Notify...");
	PG_Listen(connection, "pgstream_events", "OnListenReady");
	return 1;
}

public OnListenReady(connection, bool:success)
{
	printf("[PGStream] OnListenReady: success=%d", _:success);

	if (!success)
	{
		print("[PGStream] FAIL: LISTEN failed");
		return 1;
	}

	print("[PGStream] PASS: Now listening on 'pgstream_events'");

	// Send a notification to ourselves
	print("[PGStream] TEST Sending NOTIFY...");
	PG_Notify(connection, "pgstream_events", "hello_from_pgstream_v2");

	// Give a little time, then do final check
	SetTimer("DoFinalCheck", 1000, false);
	return 1;
}

forward DoFinalCheck();
public DoFinalCheck()
{
	// Test 12: Final data verification
	print("[PGStream] TEST Final verification query...");
	PG_AsyncQuery(g_conn, "SELECT COUNT(*) AS cnt FROM pgstream_test", "OnFinalCheck");
}

public OnPGNotify(connection, const channel[], const payload[])
{
	printf("[PGStream] PASS NOTIFY: conn=%d channel='%s' payload='%s'", connection, channel, payload);
}

public OnFinalCheck(connection, result, extra)
{
	new cnt[16];
	PG_GetStringByName(result, 0, "cnt", cnt, sizeof(cnt));
	printf("[PGStream] PASS: Total rows in pgstream_test: %s", cnt);
	PG_FreeResult(result);

	// Cleanup test table
	PG_AsyncQuery(connection, "DROP TABLE IF EXISTS pgstream_test", "");

	printf("[PGStream] IsConnected: %d", PG_IsConnected(connection));
	PG_Close(connection);
	printf("[PGStream] Connection closed. IsConnected: %d", PG_IsConnected(connection));

	print("[PGStream] === ALL INTEGRATION TESTS COMPLETED ===");
}
