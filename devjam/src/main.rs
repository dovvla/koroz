use anyhow::{Context as _, Ok};
use chrono::{self};
use event_manip::aggregate_dns_answers;
use event_manip::purge_dns_records;
use event_manip::DigRepopulator;
use event_manip::DockerDigRepopulator;
use event_manip::DockerUnboundInvalidator;
use event_manip::UnboundInvalidator;
use lazy_static::lazy_static;
use prometheus::register_int_counter_vec;
use prometheus::IntCounterVec;
use settings::settings;
use std::collections::BinaryHeap;
use std::sync::Arc;
use std::{ptr, slice};
use warp::Filter;
use warp_handlers::metrics;
use warp_handlers::{get_universe, with_universe};

use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
use log::{debug, info, warn};
use tokio::io::unix::AsyncFd;
use tokio::join;
use tokio::sync::{mpsc, watch, RwLock};

mod event_manip;
mod settings;
mod structs;
mod warp_handlers;
use structs::{DnsAnswer, DnsResponse};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp5s0")]
    iface: String,
}

lazy_static! {
    static ref ACTIONS_OVER_RECORDS_COUNTER: IntCounterVec = register_int_counter_vec!(
        "actions_over_records",
        "Number of actions over records",
        &["action"]
    )
    .unwrap();
    static ref FAILED_COMMANDS_TO_EXECUTE_COUNTER_VEC: IntCounterVec = register_int_counter_vec!(
        "failed_commands_to_execute",
        "Number of failed commands to execute",
        &["command", "exit_code"]
    )
    .unwrap();
    static ref FAILED_RECORDS_MANIPULATION_COUNTER_VEC: IntCounterVec = register_int_counter_vec!(
        "failed_records_manipulation",
        "Number of failed record maniuplations",
        &["command"]
    )
    .unwrap();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // --- Boilerplate ------------------------------------------------------------
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/devjam"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("devjam").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // --- END: Boilerplate ------------------------------------------------------------

    let ring_dump =
        aya::maps::RingBuf::try_from(ebpf.take_map("DNS_RESPONSES_RING_BUFFER").unwrap()).unwrap();

    // Channel defintions, one channel to enable "spinloop" for reading from ring buffer
    // Another channel that will act as a collector for all the propagated data
    let (_tx, rx) = watch::channel(false);
    let (t_event, r_event_collector): (mpsc::Sender<DnsResponse>, mpsc::Receiver<DnsResponse>) =
        mpsc::channel(1);

    let dns_answers = Arc::new(RwLock::new(BinaryHeap::new()));

    let read_buffer = tokio::spawn(async move {
        let mut rx = rx.clone();
        let mut async_fd = AsyncFd::new(ring_dump).unwrap();

        loop {
            tokio::select! {
                _ = async_fd.readable_mut() => {
                    let  t_event = t_event.clone();
                    let mut guard = async_fd.readable_mut().await.unwrap();
                    let rb = guard.get_inner_mut();

                    while let Some(read) = rb.next() {
                        let ptr = read.as_ptr();

                        let size = unsafe { ptr::read_unaligned::<u16>(ptr as *const u16) };
                        let data = unsafe { slice::from_raw_parts(ptr.byte_add(2).byte_add(8), size.into()) };
                        let reading_time = chrono::offset::Utc::now();

                        if let std::result::Result::Ok(response_packet) = dns_parser::Packet::parse(&data[42_usize..size as usize]) {
                            t_event.send(response_packet.answers.into_iter().map(|answer| (answer, reading_time)).map(DnsAnswer::from).collect()).await.unwrap();
                        }
                    }

                    guard.clear_ready();
                },
                _ = rx.changed() => {
                    if *rx.borrow() {
                        break;
                    }
                }
            }
        }
    });

    let collector = {
        let received_data = Arc::clone(&dns_answers);
        tokio::spawn(async move {
            aggregate_dns_answers(r_event_collector, received_data).await;
        })
    };

    let get_universe_route = warp::path("universe")
        .and(warp::get())
        .and(with_universe(dns_answers.clone()))
        .and_then(get_universe);

    let metrics_route = warp::path("metrics").and(warp::get()).and_then(metrics);

    let warp_routes = warp::get().and(get_universe_route).or(metrics_route);

    let warp_handle = {
        tokio::spawn(async move {
            warp::serve(warp_routes).run(([127, 0, 0, 1], 3030)).await;
        })
    };

    let refresher = {
        let dns_answers = Arc::clone(&dns_answers);
        match settings().we_running_docker {
            true => tokio::spawn(async move {
                purge_dns_records(
                    dns_answers,
                    DockerUnboundInvalidator::default(),
                    DockerDigRepopulator::default(),
                )
                .await;
            }),
            false => tokio::spawn(async move {
                purge_dns_records(dns_answers, UnboundInvalidator, DigRepopulator).await
            }),
        }
    };

    join!(collector, read_buffer, warp_handle, refresher);
    info!("Exiting...");
    Ok(())
}
