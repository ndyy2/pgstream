use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub pool: PoolConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    #[serde(default)]
    pub password: String,
    pub password_env: Option<String>,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_seconds: u64,
    #[serde(default = "default_query_timeout")]
    pub query_timeout_seconds: u64,
}

fn default_connect_timeout() -> u64 {
    5
}
fn default_query_timeout() -> u64 {
    15
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 5432,
            database: "samp_db".into(),
            username: "postgres".into(),
            password: "".into(),
            password_env: None,
            connect_timeout_seconds: 5,
            query_timeout_seconds: 15,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PoolConfig {
    #[serde(default = "default_pool_size")]
    pub max_size: usize,
}

fn default_pool_size() -> usize {
    5
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self { max_size: 5 }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

fn default_log_level() -> String {
    "info".into()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
        }
    }
}

impl Config {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Self {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(mut cfg) = toml::from_str::<Config>(&content) {
                if let Some(ref env_var) = cfg.database.password_env {
                    if let Ok(env_pass) = std::env::var(env_var) {
                        cfg.database.password = env_pass;
                    }
                }
                return cfg;
            }
        }
        Config::default()
    }

    pub fn default() -> Self {
        Self {
            database: DatabaseConfig::default(),
            pool: PoolConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}
