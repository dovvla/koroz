use std::io::Error;
use std::process::Output;
use std::{collections::BinaryHeap, sync::Arc};

use log::info;
use tokio::process::Command;
use tokio::sync::{mpsc, RwLock};
use tokio::task::{JoinError, JoinSet};

use crate::{
    settings,
    structs::{DnsAnswer, DnsResponse},
};
use crate::{
    ACTIONS_OVER_RECORDS_COUNTER, FAILED_COMMANDS_TO_EXECUTE_COUNTER_VEC,
    FAILED_RECORDS_MANIPULATION_COUNTER_VEC,
};

async fn process_command_end_output(
    command_end: Result<Result<Output, Error>, JoinError>,
    command_type: &str,
) {
    if let Ok(output_result) = command_end {
        match output_result {
            Ok(output) => match output.status.success() {
                true => ACTIONS_OVER_RECORDS_COUNTER
                    .with_label_values(&[if command_type == "dig" {
                        "repopulate"
                    } else {
                        "purge"
                    }])
                    .inc(),
                false => FAILED_COMMANDS_TO_EXECUTE_COUNTER_VEC
                    .with_label_values(&[
                        command_type,
                        &output.status.code().unwrap_or(-1).to_string(),
                    ])
                    .inc(),
            },
            Err(e) => {
                dbg!(e);
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
) {
    info!("Started event collector");
    while let Some(dns_answers) = rx.recv().await {
        let mut dns_responses_container = dns_answer_set.write().await;

        for dns_answer in dns_answers
            .into_iter()
            .filter(|answer| answer.has_reasonable_ttl())
        {
            dns_responses_container.push(dns_answer);
        }
    }
}

pub async fn purge_dns_records(dns_answer_set: Arc<RwLock<BinaryHeap<DnsAnswer>>>) {
    info!("Started purger/repopulator");
    loop {
        let mut read_dns_answers = dns_answer_set.write().await;

        let mut records_for_purging = vec![];
        while let Some(answer) = read_dns_answers.pop() {
            records_for_purging.push(answer);
            if records_for_purging.len() == settings::settings().max_records_to_refresh_in_cycle {
                break;
            }
        }
        let mut invalidation_commands: JoinSet<_> = records_for_purging
            .iter()
            .map(|record| match settings::settings().we_running_docker {
                true => {
                    let mut cmd = Command::new("docker");
                    cmd.arg("exec")
                        .arg("-it")
                        .arg("my-unbound")
                        .arg("unbound-control")
                        .arg("flush")
                        .arg(record.domain_name.clone())
                        .kill_on_drop(true);
                    cmd.output()
                }
                false => {
                    let mut cmd = Command::new("unbound-control");
                    cmd.arg("flush")
                        .arg(record.domain_name.clone())
                        .kill_on_drop(true);
                    cmd.output()
                }
            })
            .collect();
        while let Some(command_end) = invalidation_commands.join_next().await {
            process_command_end_output(command_end, "invalidate").await;
        }

        let mut repopulation_commands: JoinSet<_> = records_for_purging
            .iter()
            .map(|record| match settings::settings().we_running_docker {
                true => {
                    let mut cmd = Command::new("docker");
                    cmd.arg("exec")
                        .arg("-it")
                        .arg("my-unbound")
                        .arg("dig")
                        .arg(record.domain_name.clone())
                        .kill_on_drop(true);
                    cmd.output()
                }
                false => {
                    let mut cmd = Command::new("dig");
                    cmd.arg(record.domain_name.clone()).kill_on_drop(true);
                    cmd.output()
                }
            })
            .collect();

        while let Some(command_end) = repopulation_commands.join_next().await {
            process_command_end_output(command_end, "repopulate").await;
        }

        info!("Finished iteration");
        tokio::time::sleep(tokio::time::Duration::from_secs(
            settings::settings().purge_wake_up_interval,
        ))
        .await;
    }
}
