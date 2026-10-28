//! Unit tests for the printf-Pawn style SQL formatter (pure, no DB).

use pgstream::database::format::{convert_pawn_format, scan_specifiers, FormatArgKind};
use pgstream::database::parameters::SqlParam;

fn i(v: i32) -> SqlParam {
    SqlParam::Int(v)
}
fn f(v: f64) -> SqlParam {
    SqlParam::Float(v)
}
fn s(v: &str) -> SqlParam {
    SqlParam::String(v.to_string())
}

#[test]
fn insert_mixed_specifiers_becomes_placeholders() {
    let (sql, params) = convert_pawn_format(
        "INSERT INTO t (a,b) VALUES (%s, %i)",
        &[s("O'Reilly"), i(7)],
    )
    .unwrap();
    assert_eq!(sql, "INSERT INTO t (a,b) VALUES ($1, $2)");
    assert_eq!(params[0], SqlParam::String("O'Reilly".into()));
    assert_eq!(params[1], SqlParam::Int(7));
}

#[test]
fn all_specifiers_used_once() {
    let (sql, params) = convert_pawn_format(
        "SELECT * FROM t WHERE a = %d AND b = %i AND c = %f AND d = %s AND e = %c AND f = %x AND g = %X",
        &[i(1), i(2), f(3.5), s("hi"), i(65), i(255), i(255)],
    )
    .unwrap();
    assert_eq!(sql, "SELECT * FROM t WHERE a = $1 AND b = $2 AND c = $3 AND d = $4 AND e = $5 AND f = $6 AND g = $7");
    assert_eq!(params[4], SqlParam::String("A".into()));
    assert_eq!(params[5], SqlParam::String("ff".into()));
    assert_eq!(params[6], SqlParam::String("FF".into()));
}

#[test]
fn percent_inside_string_literal_untouched() {
    let (sql, params) =
        convert_pawn_format("SELECT * FROM t WHERE name LIKE '%O%' AND id = %d", &[i(9)]).unwrap();
    assert_eq!(sql, "SELECT * FROM t WHERE name LIKE '%O%' AND id = $1");
    assert_eq!(params.len(), 1);
}

#[test]
fn escape_percent_yields_literal_percent() {
    let (sql, params) =
        convert_pawn_format("SELECT score > 50 %% FROM t WHERE id = %d", &[i(1)]).unwrap();
    assert_eq!(sql, "SELECT score > 50 % FROM t WHERE id = $1");
    assert_eq!(params.len(), 1);
}

#[test]
fn comments_are_left_alone() {
    let (sql, params) = convert_pawn_format(
        "-- %s rule\nSELECT /* %i */ * FROM t WHERE id = %i",
        &[i(3)],
    )
    .unwrap();
    assert_eq!(sql, "-- %s rule\nSELECT /* %i */ * FROM t WHERE id = $1");
    assert_eq!(params.len(), 1);
}

#[test]
fn quoted_identifier_untouched() {
    let (sql, params) =
        convert_pawn_format("SELECT \"col_%i\" FROM t WHERE id = %i", &[i(2)]).unwrap();
    assert_eq!(sql, "SELECT \"col_%i\" FROM t WHERE id = $1");
    assert_eq!(params.len(), 1);
}

#[test]
fn escaped_quote_keeps_placeholder_out_of_literal() {
    // %s inside the literal stays literal text.
    let (sql, params) =
        convert_pawn_format("SELECT 'it''s %s gone' FROM t WHERE id = %i", &[i(1)]).unwrap();
    assert_eq!(sql, "SELECT 'it''s %s gone' FROM t WHERE id = $1");
    assert_eq!(params.len(), 1);
}

#[test]
fn injection_stays_bound() {
    let input = "Robert'); DROP TABLE Students;--";
    let (sql, _) = convert_pawn_format("SELECT * FROM t WHERE name = %s", &[s(input)]).unwrap();
    assert_eq!(sql, "SELECT * FROM t WHERE name = $1");
}

#[test]
fn string_edge_cases() {
    // empty string
    let (_, params) =
        convert_pawn_format("SELECT %s, %s, %s", &[s(""), SqlParam::Null, s("héllo 🎉")]).unwrap();
    assert_eq!(params[0], SqlParam::String("".into()));
    assert_eq!(params[1], SqlParam::Null);
    assert_eq!(params[2], SqlParam::String("héllo 🎉".into()));
}

#[test]
fn char_and_hex_binding() {
    let (_, params) = convert_pawn_format("%c %x %X", &[i(65), i(255), i(255)]).unwrap();
    assert_eq!(params[0], SqlParam::String("A".into()));
    assert_eq!(params[1], SqlParam::String("ff".into()));
    assert_eq!(params[2], SqlParam::String("FF".into()));
}

#[test]
fn count_mismatch_both_ways() {
    let got = convert_pawn_format("SELECT * FROM t WHERE a = %d", &[i(1), i(2)]);
    assert_eq!(
        got.err().unwrap(),
        "format specifier count mismatch (expected 1, got 2)"
    );
    let got = convert_pawn_format("SELECT * FROM t WHERE a = %d AND b = %i", &[i(1)]);
    assert_eq!(
        got.err().unwrap(),
        "format specifier count mismatch (expected 2, got 1)"
    );
}

#[test]
fn unknown_specifier_rejected() {
    let got = convert_pawn_format("SELECT %q", &[]);
    assert_eq!(got.err().unwrap(), "unsupported format specifier '%q'");
}

#[test]
fn trailing_percent_rejected() {
    let got = convert_pawn_format("SELECT 1 %", &[]);
    assert_eq!(got.err().unwrap(), "unsupported format specifier '%'");
}

#[test]
fn unicode_outside_specifiers_survives() {
    let (sql, _) = convert_pawn_format("SELECT '🎉' WHERE id = %d", &[i(1)]).unwrap();
    assert_eq!(sql, "SELECT '🎉' WHERE id = $1");
}

#[test]
fn mysql_compat_e_and_precision_specs() {
    // %e (escaped string) binds as a plain string param.
    let (sql, kinds) = scan_specifiers("INSERT INTO t (name, score) VALUES (%e, %d)").unwrap();
    assert_eq!(sql, "INSERT INTO t (name, score) VALUES ($1, $2)");
    assert_eq!(kinds, vec![FormatArgKind::Str, FormatArgKind::Int]);

    // Precision flags like %.2f / %.4f are skipped, still bind float.
    let (sql, kinds) = scan_specifiers("UPDATE t SET x = %.2f, y = %.4f WHERE id = %05d").unwrap();
    assert_eq!(sql, "UPDATE t SET x = $1, y = $2 WHERE id = $3");
    assert_eq!(
        kinds,
        vec![
            FormatArgKind::Float,
            FormatArgKind::Float,
            FormatArgKind::Int
        ]
    );
}
