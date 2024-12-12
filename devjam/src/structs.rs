use std::{collections::BTreeSet, sync::Arc};

use chrono::{DateTime, TimeDelta, Utc};
use dns_parser::{Class, RData, ResourceRecord};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

pub type DnsResponse = Vec<DnsAnswer>;

pub type Universe = Arc<RwLock<BTreeSet<DnsAnswer>>>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecordType {
    A,
    AAAA,
    Other,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Cls {
    IN,
    CS,
    CH,
    HS,
}

impl From<RData<'_>> for RecordType {
    fn from(data: RData<'_>) -> Self {
        match data {
            dns_parser::RData::A(_) => RecordType::A,
            dns_parser::RData::AAAA(_) => RecordType::AAAA,
            _ => RecordType::Other,
        }
    }
}

impl From<Class> for Cls {
    fn from(class: Class) -> Self {
        match class {
            Class::IN => Cls::IN,
            Class::CS => Cls::CS,
            Class::CH => Cls::CH,
            Class::HS => Cls::HS,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsAnswer {
    pub domain_name: String,
    pub ttl: u32,
    pub cls: Cls,
    pub record_type: RecordType,
    pub read_from_buffer_ts: DateTime<Utc>,
}

impl From<(ResourceRecord<'_>, DateTime<Utc>)> for DnsAnswer {
    fn from(t: (ResourceRecord<'_>, DateTime<Utc>)) -> Self {
        DnsAnswer {
            domain_name: t.0.name.to_string().clone(),
            ttl: t.0.ttl,
            cls: t.0.cls.into(),
            record_type: t.0.data.into(),
            read_from_buffer_ts: t.1,
        }
    }
}

impl DnsAnswer {
    pub fn expiration_time(&self) -> DateTime<Utc> {
        self.read_from_buffer_ts
            .checked_sub_signed(TimeDelta::seconds(self.ttl.into()))
            .unwrap_or(DateTime::<Utc>::MAX_UTC)
    }
}

impl PartialOrd for DnsAnswer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if self.expiration_time() == other.expiration_time() {
            Some(std::cmp::Ordering::Equal)
        } else {
            match self.expiration_time() > other.expiration_time() {
                true => Some(std::cmp::Ordering::Less),
                false => Some(std::cmp::Ordering::Greater),
            }
        }
    }
}

impl Ord for DnsAnswer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.expiration_time() == other.expiration_time() {
            std::cmp::Ordering::Equal
        } else {
            match self.expiration_time() > other.expiration_time() {
                true => std::cmp::Ordering::Less,
                false => std::cmp::Ordering::Greater,
            }
        }
    }
}
