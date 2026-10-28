use pgstream::abi::amx::*;
use pgstream::config::Config;
use pgstream::database::result::QueryResult;

#[test]
fn test_abi_constants_match_samp_sdk() {
    assert_eq!(SAMP_PLUGIN_VERSION, 0x0200);
    assert_eq!(SUPPORTS_AMX_NATIVES, 0x10000);
    assert_eq!(SUPPORTS_PROCESS_TICK, 0x20000);
    assert_eq!(slot::LOGPRINTF, 0x00);
    assert_eq!(slot::AMX_EXPORTS, 0x10);
    assert_eq!(slot::REGISTER, 33);
    assert_eq!(slot::GET_ADDR, 13);
    assert_eq!(slot::SET_STRING, 37);
}

#[test]
fn test_native_arg_bounds() {
    // Real ABI (proven live on samp-server 0.3.7-R2): params[0] = n args in bytes (n*4)
    let mut params = [8 as Cell, 100 as Cell, 200 as Cell];
    unsafe {
        assert_eq!(native_arg(params.as_mut_ptr(), 0), None);
        assert_eq!(native_arg(params.as_mut_ptr(), 1), Some(100));
        assert_eq!(native_arg(params.as_mut_ptr(), 2), Some(200));
        assert_eq!(native_arg(params.as_mut_ptr(), 3), None);
    }
}

#[test]
fn test_query_result_named_columns_and_nulls() {
    let cols = vec!["id".into(), "Username".into(), "Score".into(), "Bio".into()];
    let rows = vec![
        vec![Some("1".into()), Some("Axelon".into()), Some("100".into()), None],
        vec![Some("2".into()), Some("Player2".into()), None, Some("Hello".into())],
    ];
    let res = QueryResult::new(cols, rows, 2);

    assert_eq!(res.get_col_index("ID"), Some(0));
    assert_eq!(res.get_col_index("username"), Some(1));
    assert_eq!(res.get_col_index("SCORE"), Some(2));
    assert_eq!(res.get_col_index("nonexistent"), None);

    assert_eq!(res.is_null(0, 3), true);
    assert_eq!(res.is_null(0, 1), false);
    assert_eq!(res.get_value(0, 1), Some("Axelon"));

    assert_eq!(res.is_null(1, 2), true);
    assert_eq!(res.get_value(1, 3), Some("Hello"));
}

#[test]
fn test_config_defaults() {
    let cfg = Config::default();
    assert_eq!(cfg.database.port, 5432);
    assert_eq!(cfg.pool.max_size, 5);
}
