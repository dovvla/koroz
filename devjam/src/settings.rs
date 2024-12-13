use config::{Config, File};
use serde::{Deserialize, Serialize};

pub fn settings() -> Settings {
    Config::builder()
        .add_source(File::with_name("Settings.toml"))
        .build()
        .unwrap()
        .try_deserialize::<Settings>()
        .unwrap()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub purge_wake_up_interval: u64,
    pub max_records_to_refresh_in_cycle: usize,
    pub min_ttl_to_keep_record: u32,
    pub max_ttl_to_keep_record: u32,
    pub we_running_docker: bool,
    pub min_time_to_expire_to_purge: i64,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            purge_wake_up_interval: 5,
            min_ttl_to_keep_record: 30,
            max_ttl_to_keep_record: 3600,
            max_records_to_refresh_in_cycle: 100,
            we_running_docker: false,
            min_time_to_expire_to_purge: 300,
        }
    }
}
