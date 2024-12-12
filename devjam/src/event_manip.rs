use std::{collections::BTreeSet, sync::Arc};

use log::info;
use tokio::sync::{mpsc, RwLock};

use crate::structs::{DnsAnswer, DnsResponse};

pub async fn event_collector(
    mut rx: mpsc::Receiver<DnsResponse>,
    dns_responses_container: Arc<RwLock<BTreeSet<DnsAnswer>>>,
) {
    info!("Started event collector");
    while let Some(dns_answers) = rx.recv().await {
        let mut dns_responses_container = dns_responses_container.write().await;
        for dns_answer in dns_answers {
            dns_responses_container.insert(dns_answer);
        }
    }
}
