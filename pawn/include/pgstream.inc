/*
 *  pgstream — native PostgreSQL plugin for SA:MP
 *  Version 0.3.2
 *
 *  Features: TLS/SSL, Transactions, Listen/Notify, Prepared Statements,
 *            Parameterized Queries, printf-style QueryFormat (%d/%i/%f/%s/%c/%x/%X),
 *            Result API (index & name), Auto-Reconnect (supervisor keeps handles alive).
 */
#if defined _pgstream_included
	#endinput
#endif
#define _pgstream_included

#define PGSTREAM_VERSION 302

// Plugin version info
native PG_Version(dest[], size = sizeof(dest));

// ---------------------------------------------------------------------------
// Connection management
// ---------------------------------------------------------------------------

// Connect with individual parameters (NoTLS)
native PG_Connect(const host[], const user[], const password[], const database[], port = 5432, const callback[] = "");

// Connect with a URL string (auto TLS if sslmode= in URL)
// Example: PG_ConnectUrl("postgresql://user:pass@host:5432/db?sslmode=require", "OnConnect");
native PG_ConnectUrl(const url[], const callback[] = "");

// Close a connection handle
native PG_Close(connection);

// Check if a connection is alive
native bool:PG_IsConnected(connection);

// Get last error message
native PG_GetError(connection, dest[], size = sizeof(dest));

// Escape a string for safe SQL usage
native PG_EscapeString(connection, const src[], dest[], size = sizeof(dest));

// ---------------------------------------------------------------------------
// Asynchronous Query Execution
// ---------------------------------------------------------------------------

// Callback signature: forward OnQueryComplete(connection, result, extra);
// Formats: 'i'/'d' (int), 'f' (float), 's' (string), 'b' (bool), 'n' (null)
// Parameters use $1, $2, ... placeholders
native PG_AsyncQuery(connection, const query[], const callback[] = "", const format[] = "", {Float, _}:...);

// printf-style formatter: specifiers %d/%i/%f/%s/%c/%x/%X in the query
// become $1..$N parameter bindings (never string interpolation).
// '%' inside SQL string literals ('...'), quoted identifiers ("..."), and
// SQL comments is left untouched; %% is a literal percent.
// varargs follow specifier order: %d/%i/%x/%X/%c = int cell, %f = float, %s = string.
native PG_QueryFormat(connection, const query[], const callback[] = "", {Float, _}:...);

// ---------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------

// Callback signature: forward OnTransactionCmd(connection, bool:success);
native PG_Begin(connection, const callback[] = "");
native PG_Commit(connection, const callback[] = "");
native PG_Rollback(connection, const callback[] = "");

// ---------------------------------------------------------------------------
// Listen / Notify (Pub/Sub)
// ---------------------------------------------------------------------------

// Subscribe to a PostgreSQL notification channel
// Notifications dispatch to: forward OnPGNotify(connection, const channel[], const payload[]);
// Optional callback for LISTEN command result: forward OnListenReady(connection, bool:success);
native PG_Listen(connection, const channel[], const callback[] = "");

// Send a notification to a channel
native PG_Notify(connection, const channel[], const payload[] = "");

// ---------------------------------------------------------------------------
// Prepared Statements
// ---------------------------------------------------------------------------

// Prepare a named statement for repeated execution
// Callback signature: forward OnPrepared(connection, bool:success);
native PG_Prepare(connection, const stmt_name[], const query[], const callback[] = "");

// Execute a previously prepared statement (same format string as PG_AsyncQuery)
// Callback signature: forward OnQueryComplete(connection, result, extra);
native PG_ExecutePrepared(connection, const stmt_name[], const callback[] = "", const format[] = "", {Float, _}:...);

// ---------------------------------------------------------------------------
// Result inspection by column index
// ---------------------------------------------------------------------------

native PG_NumRows(result);
native PG_NumFields(result);
native PG_GetAffectedRows(result);
native PG_GetString(result, row, col, dest[], size = sizeof(dest));
native PG_GetInt(result, row, col);
native Float:PG_GetFloat(result, row, col);
native bool:PG_IsNull(result, row, col);
native PG_FieldName(result, col, dest[], size = sizeof(dest));

// ---------------------------------------------------------------------------
// Result inspection by column name
// ---------------------------------------------------------------------------

native PG_GetStringByName(result, row, const col_name[], dest[], size = sizeof(dest));
native PG_GetIntByName(result, row, const col_name[]);
native Float:PG_GetFloatByName(result, row, const col_name[]);
native bool:PG_IsNullByName(result, row, const col_name[]);

// ---------------------------------------------------------------------------
// Result memory release
// ---------------------------------------------------------------------------

native PG_FreeResult(result);
