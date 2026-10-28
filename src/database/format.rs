//! printf-Pawn style SQL formatter: converts `%d %i %f %s %c %x %X %%`
//! inside a query into PostgreSQL `$N` placeholders plus `SqlParam` values.

use crate::database::parameters::SqlParam;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatArgKind {
    Int,
    Float,
    Str,
    Char,
    Hex,
    HexUpper,
}

/// Scan a query printf-Pawn style: replace `%spec` outside SQL string literals
/// / quoted identifiers / comments with `$N` placeholders and report the
/// expected argument kinds in binding order.
///
/// `%` inside `'...'` literals (e.g. `LIKE '%x%'`) is left untouched — build
/// LIKE patterns as bound `$1` parameters instead, passing pattern text as a
/// `%s` argument in value position.
pub fn scan_specifiers(input: &str) -> Result<(String, Vec<FormatArgKind>), String> {
    let mut out = String::with_capacity(input.len());
    let mut kinds: Vec<FormatArgKind> = Vec::new();
    let mut iter = input.chars().peekable();
    let peek_ch = |iter: &mut std::iter::Peekable<std::str::Chars>| iter.peek().copied();

    while let Some(ch) = iter.next() {
        match ch {
            '\'' => {
                // SQL string literal; '' escapes a quote inside.
                out.push('\'');
                while let Some(c) = iter.next() {
                    if c == '\'' {
                        if peek_ch(&mut iter) == Some('\'') {
                            out.push_str("''");
                            iter.next();
                            continue;
                        }
                        break;
                    }
                    out.push(c);
                }
                out.push('\'');
            }
            '"' => {
                // Quoted identifier.
                out.push('"');
                for c in iter.by_ref() {
                    if c == '"' {
                        break;
                    }
                    out.push(c);
                }
                out.push('"');
            }
            '-' if peek_ch(&mut iter) == Some('-') => {
                // Line comment: until (exclusive) newline.
                iter.next();
                out.push_str("--");
                for c in iter.by_ref() {
                    if c == '\n' {
                        out.push('\n');
                        break;
                    }
                    out.push(c);
                }
            }
            '/' if peek_ch(&mut iter) == Some('*') => {
                // Block comment.
                iter.next();
                out.push_str("/*");
                while let Some(c) = iter.next() {
                    if c == '*' && peek_ch(&mut iter) == Some('/') {
                        iter.next();
                        out.push_str("*/");
                        break;
                    }
                    out.push(c);
                }
            }
            '%' => {
                // Skip optional flags/width/precision (e.g. `%.2f`, `%05d`)
                // before the conversion letter — precision is irrelevant for
                // bound parameters.
                let mut next = peek_ch(&mut iter);
                while let Some(c) = next {
                    if c.is_ascii_digit() || matches!(c, '.' | '-' | '+' | ' ' | '#' | '0' | '*') {
                        iter.next();
                        next = peek_ch(&mut iter);
                    } else {
                        break;
                    }
                }
                let kind = match next {
                    Some('d') | Some('i') => Some(FormatArgKind::Int),
                    Some('f') => Some(FormatArgKind::Float),
                    // MySQL-plugin style escaped string; binding makes it
                    // safe already, so it maps to a plain string parameter.
                    Some('s') | Some('e') | Some('q') => Some(FormatArgKind::Str),
                    Some('c') => Some(FormatArgKind::Char),
                    Some('x') => Some(FormatArgKind::Hex),
                    Some('X') => Some(FormatArgKind::HexUpper),
                    _ => None,
                };
                if next == Some('%') {
                    out.push('%');
                    iter.next();
                } else if let Some(kind) = kind {
                    out.push_str(&format!("${}", kinds.len() + 1));
                    kinds.push(kind);
                    iter.next();
                } else {
                    return Err(format!(
                        "unsupported format specifier '%{}'",
                        next.map(|c| c.to_string()).unwrap_or_default()
                    ));
                }
            }
            _ => out.push(ch),
        }
    }

    Ok((out, kinds))
}

/// Convert a printf-Pawn style query into `$N` placeholders with typed,
/// bound `SqlParam` values. Values never go into the raw SQL string, so
/// user input cannot cause injection.
pub fn convert_pawn_format(
    input: &str,
    args: &[SqlParam],
) -> Result<(String, Vec<SqlParam>), String> {
    let (sql, kinds) = scan_specifiers(input)?;
    if args.len() != kinds.len() {
        return Err(format!(
            "format specifier count mismatch (expected {}, got {})",
            kinds.len(),
            args.len()
        ));
    }

    let params: Vec<SqlParam> = kinds
        .iter()
        .zip(args)
        .map(|(kind, arg)| match kind {
            FormatArgKind::Int | FormatArgKind::Float | FormatArgKind::Str => arg.clone(),
            FormatArgKind::Char => match arg {
                SqlParam::Int(v) => {
                    SqlParam::String(char::from_u32(*v as u32).unwrap_or(' ').to_string())
                }
                SqlParam::String(s) => SqlParam::String(s.clone()),
                _ => SqlParam::Null,
            },
            FormatArgKind::Hex => match arg {
                SqlParam::Int(v) => SqlParam::String(format!("{:x}", v)),
                _ => SqlParam::Null,
            },
            FormatArgKind::HexUpper => match arg {
                SqlParam::Int(v) => SqlParam::String(format!("{:X}", v)),
                _ => SqlParam::Null,
            },
        })
        .collect();

    Ok((sql, params))
}
