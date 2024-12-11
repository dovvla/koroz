use std::sync::Arc;

use chrono::{DateTime, Utc};
use dns_parser::ResourceRecord;
use serde::{ser::SerializeStruct, Serialize};
use tokio::sync::RwLock;

pub type DnsResponse<'a> = (Vec<MyResourceRecord<'a>>, DateTime<Utc>);

pub type Universe<'a> = Arc<RwLock<Vec<DnsResponse<'a>>>>;

#[derive(Serialize)]
pub struct DnsResponseWrapper<'a> {
    pub responses: Vec<DnsResponse<'a>>,
}

#[derive(Debug)]
pub struct MyResourceRecord<'a>(pub ResourceRecord<'a>);

impl<'a> Clone for MyResourceRecord<'a> {
    fn clone(&self) -> Self {
        MyResourceRecord(ResourceRecord {
            name: self.0.name,
            multicast_unique: self.0.multicast_unique,
            cls: self.0.cls,
            ttl: self.0.ttl,
            data: match &self.0.data {
                dns_parser::RData::A(record) => dns_parser::RData::A(*record),
                dns_parser::RData::AAAA(record) => dns_parser::RData::AAAA(*record),
                dns_parser::RData::CNAME(record) => dns_parser::RData::CNAME(*record),
                dns_parser::RData::MX(record) => dns_parser::RData::MX(*record),
                dns_parser::RData::NS(record) => dns_parser::RData::NS(*record),
                dns_parser::RData::PTR(record) => dns_parser::RData::PTR(*record),
                dns_parser::RData::SOA(record) => dns_parser::RData::SOA(*record),
                dns_parser::RData::SRV(record) => dns_parser::RData::SRV(*record),
                dns_parser::RData::TXT(record) => dns_parser::RData::TXT(record.clone()),
                dns_parser::RData::Unknown(data) => dns_parser::RData::Unknown(data.clone()),
            },
        })
    }
}

impl Serialize for MyResourceRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("ResourceRecord", 5)?;

        state.serialize_field("name", &self.0.name.to_string())?;
        state.serialize_field("multicast_unique", &self.0.multicast_unique)?;
        // state.serialize_field("cls", &self.cls as usize)?;
        state.serialize_field("ttl", &self.0.ttl)?;
        match &self.0.data {
            dns_parser::RData::A(_record) => {
                state.serialize_field("record_type", "A")?;
            }
            dns_parser::RData::AAAA(_record) => {
                state.serialize_field("record_type", "AAAA")?;
            }
            dns_parser::RData::CNAME(_record) => {
                state.serialize_field("record_type", "CNAME")?;
            }
            dns_parser::RData::MX(_record) => {
                state.serialize_field("record_type", "MX")?;
            }
            dns_parser::RData::NS(_record) => {
                state.serialize_field("record_type", "NS")?;
            }
            dns_parser::RData::PTR(_record) => {
                state.serialize_field("record_type", "PTR")?;
            }
            dns_parser::RData::SOA(_record) => {
                state.serialize_field("record_type", "SOA")?;
            }
            dns_parser::RData::SRV(_record) => {
                state.serialize_field("record_type", "SRV")?;
            }
            dns_parser::RData::TXT(_record) => {
                state.serialize_field("record_type", "TXT")?;
            }
            dns_parser::RData::Unknown(_) => todo!(),
        }
        state.end()
    }
}
