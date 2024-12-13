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
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            purge_wake_up_interval: 10,
            max_ttl_to_keep_record: 7200,
            min_ttl_to_keep_record: 15,
            max_records_to_refresh_in_cycle: 100,
            we_running_docker: false,
        }
    }
}
