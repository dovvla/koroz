use std::sync::Arc;

use log::info;
use tokio::sync::{mpsc, RwLock};

use crate::structs::DnsResponse;

pub async fn event_collector<'a, C>(
    mut rx: mpsc::Receiver<DnsResponse<'a>>,
    dns_responses_container: Arc<RwLock<C>>,
) where
    C: Default + Extend<DnsResponse<'a>>,
{
    info!("Started event collector");
    while let Some(resource_records) = rx.recv().await {
        // Acquire a write lock to modify the dns_responses_container
        let mut dns_responses_container = dns_responses_container.write().await;
        dns_responses_container.extend(std::iter::once(resource_records));
    }
}
