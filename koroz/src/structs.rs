use std::{collections::BinaryHeap, sync::Arc};

use chrono::{DateTime, TimeDelta, Utc};
use dns_parser::{Class, RData, ResourceRecord};
use serde::{Deserialize, Serialize};
use sqlx::prelude::{FromRow, Type};
use tokio::sync::RwLock;

use crate::settings::{self};

pub type DnsResponse = Vec<DnsAnswer>;

pub type Universe = Arc<RwLock<BinaryHeap<DnsAnswer>>>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Type)]
pub enum RecordType {
    A = 1,
    AAAA = 2,
    CNAME = 3,
    MX = 4,
    TXT = 5,
    Other = 6,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Type)]
pub enum Cls {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, FromRow)]
pub struct DnsAnswer {
    pub domain_name: String,
    pub ttl: u32,
    pub cls: Cls,
    pub record_type: RecordType,
    pub read_from_buffer_ts: DateTime<Utc>,
}

impl RecordType {
    pub fn form_for_command_line_arg(&self) -> &str {
        match self {
            RecordType::A => "a",
            RecordType::AAAA => "aaaa",
            RecordType::CNAME => "cname",
            RecordType::MX => "mx",
            RecordType::TXT => "txt",
            RecordType::Other => "any",
        }
    }
}

impl From<RData<'_>> for RecordType {
    fn from(data: RData<'_>) -> Self {
        match data {
            dns_parser::RData::A(_) => RecordType::A,
            dns_parser::RData::AAAA(_) => RecordType::AAAA,
            dns_parser::RData::CNAME(_) => RecordType::CNAME,
            dns_parser::RData::MX(_) => RecordType::MX,
            dns_parser::RData::TXT(_) => RecordType::TXT,
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
            .checked_add_signed(TimeDelta::seconds(self.ttl.into()))
            .unwrap_or(DateTime::<Utc>::MAX_UTC)
    }

    pub fn has_reasonable_ttl(&self) -> bool {
        self.ttl > settings::settings().min_ttl_to_keep_record
            && self.ttl < settings::settings().max_ttl_to_keep_record
    }
}

impl PartialOrd for DnsAnswer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
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
