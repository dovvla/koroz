use std::collections::HashMap;
use std::io::Error;
use std::process::Output;
use std::{collections::BinaryHeap, sync::Arc};

use chrono::{DateTime, Duration, Utc};
use log::info;
use tokio::process::Command;
use tokio::sync::{mpsc, RwLock};
use tokio::task::{JoinError, JoinSet};

use crate::structs::RecordType;
use crate::{
    settings,
    structs::{DnsAnswer, DnsResponse},
};
use crate::{
    ACTIONS_OVER_RECORDS_COUNTER, FAILED_COMMANDS_TO_EXECUTE_COUNTER_VEC,
    FAILED_RECORDS_MANIPULATION_COUNTER_VEC, RECORDS_FOR_PURGING_SIZE,
};

pub trait DnsInvalidate {
    fn command_invalidate_name(&self, domain_name: &str, record_type: &RecordType) -> Command;
}

pub trait DnsRepopulate {
    fn command_repopulate_name(&self, domain_name: &str, record_type: &RecordType) -> Command;
}

#[derive(Default, Debug)]
pub struct UnboundInvalidator;
#[derive(Default, Debug)]
pub struct DockerUnboundInvalidator;

#[derive(Default, Debug)]
pub struct DigRepopulator;
#[derive(Default, Debug)]

pub struct DockerDigRepopulator;

impl DnsInvalidate for UnboundInvalidator {
    fn command_invalidate_name(&self, domain_name: &str, record_type: &RecordType) -> Command {
        let mut cmd = Command::new("unbound-control");
        cmd.arg("flush")
            .kill_on_drop(true)
            .arg(domain_name)
            .arg(record_type.form_for_command_line_arg());
        ACTIONS_OVER_RECORDS_COUNTER
            .with_label_values(&["invalidate", record_type.form_for_command_line_arg()])
            .inc();
        cmd
    }
}

impl DnsInvalidate for DockerUnboundInvalidator {
    fn command_invalidate_name(&self, domain_name: &str, record_type: &RecordType) -> Command {
        let mut cmd = Command::new("docker");
        cmd.arg("exec")
            .arg("-it")
            .arg("my-unbound")
            .arg("unbound-control")
            .arg("flush")
            .kill_on_drop(true)
            .arg(domain_name)
            .arg(record_type.form_for_command_line_arg());
        ACTIONS_OVER_RECORDS_COUNTER
            .with_label_values(&["invalidate", record_type.form_for_command_line_arg()])
            .inc();
        cmd
    }
}

impl DnsRepopulate for DigRepopulator {
    fn command_repopulate_name(&self, domain_name: &str, record_type: &RecordType) -> Command {
        let mut cmd = Command::new("dig");
        cmd.arg(domain_name)
            .arg("-t")
            .arg(record_type.form_for_command_line_arg())
            .kill_on_drop(true);
        ACTIONS_OVER_RECORDS_COUNTER
            .with_label_values(&["repopulate", record_type.form_for_command_line_arg()])
            .inc();
        cmd
    }
}
impl DnsRepopulate for DockerDigRepopulator {
    fn command_repopulate_name(&self, domain_name: &str, record_type: &RecordType) -> Command {
        let mut cmd = Command::new("docker");
        cmd.arg("exec")
            .arg("-it")
            .arg("my-unbound")
            .arg("dig")
            .arg("-t")
            .arg(record_type.form_for_command_line_arg())
            .kill_on_drop(true)
            .arg(domain_name);
        ACTIONS_OVER_RECORDS_COUNTER
            .with_label_values(&["repopulate", record_type.form_for_command_line_arg()])
            .inc();
        cmd
    }
}

async fn process_command_end_output(
    command_end: Result<Result<Output, Error>, JoinError>,
    command_type: &str,
) {
    if let Ok(output_result) = command_end {
        match output_result {
            Ok(output) => match output.status.success() {
                true => {}
                false => {
                    dbg!(&output);
                    FAILED_COMMANDS_TO_EXECUTE_COUNTER_VEC
                        .with_label_values(&[
                            command_type,
                            &output.status.code().unwrap_or(-1).to_string(),
                        ])
                        .inc()
                }
            },
            Err(_) => {
                FAILED_RECORDS_MANIPULATION_COUNTER_VEC
                    .with_label_values(&[command_type])
                    .inc();
            }
        }
    }
}

pub async fn aggregate_dns_answers(
    mut rx: mpsc::Receiver<DnsResponse>,
    dns_answer_set: Arc<RwLock<BinaryHeap<DnsAnswer>>>,
    last_seen_answers: Arc<RwLock<HashMap<(String, RecordType), DateTime<Utc>>>>,
) {
    info!("Started event collector");
    while let Some(dns_answers) = rx.recv().await {
        let mut dns_responses_container = dns_answer_set.write().await;
        let mut last_seen_answers = last_seen_answers.write().await;
        for dns_answer in dns_answers
            .into_iter()
            .filter(|answer| answer.has_reasonable_ttl())
        {
            dns_responses_container.push(dns_answer.clone());
            last_seen_answers.insert(
                (
                    dns_answer.domain_name.clone(),
                    dns_answer.record_type.clone(),
                ),
                dns_answer.expiration_time(),
            );
        }
    }
}

pub async fn purge_dns_records<I: DnsInvalidate, R: DnsRepopulate>(
    dns_answer_set: Arc<RwLock<BinaryHeap<DnsAnswer>>>,
    invalidation: I,
    repopulation: R,
    last_seen_answers: Arc<RwLock<HashMap<(String, RecordType), DateTime<Utc>>>>,
) {
    info!("Started purger/repopulator");
    let min_time_to_expire_to_purge = settings().min_time_to_expire_to_purge;
    loop {
        let mut read_dns_answers = dns_answer_set.write().await;
        let last_seen_answers = last_seen_answers.read().await;

        let mut records_for_purging = vec![];
        while let Some(answer) = read_dns_answers.peek() {
            match answer.expiration_time().signed_duration_since(Utc::now())
                > Duration::seconds(min_time_to_expire_to_purge)
            {
                true => break,
                false => {}
            }
            let answer = read_dns_answers.pop().unwrap();
            match last_seen_answers.get(&(answer.domain_name.clone(), answer.record_type.clone())) {
                Some(dt) => {
                    if dt == &answer.expiration_time() {
                        records_for_purging.push(answer);
                    }
                }
                None => {
                    records_for_purging.push(answer);
                }
            }
            if records_for_purging.len() == settings::settings().max_records_to_refresh_in_cycle {
                break;
            }
        }
        let mut invalidation_commands: JoinSet<_> = records_for_purging
            .iter()
            .map(|record| {
                invalidation
                    .command_invalidate_name(&record.domain_name, &record.record_type)
                    .output()
            })
            .collect();
        while let Some(command_end) = invalidation_commands.join_next().await {
            process_command_end_output(command_end, "invalidate").await;
        }

        let mut repopulation_commands: JoinSet<_> = records_for_purging
            .iter()
            .map(|record| {
                repopulation
                    .command_repopulate_name(&record.domain_name, &record.record_type)
                    .output()
            })
            .collect();

        while let Some(command_end) = repopulation_commands.join_next().await {
            process_command_end_output(command_end, "repopulate").await;
        }
        RECORDS_FOR_PURGING_SIZE.set(read_dns_answers.len() as f64);

        tokio::time::sleep(tokio::time::Duration::from_secs(
            settings::settings().purge_wake_up_interval,
        ))
        .await;
    }
}
