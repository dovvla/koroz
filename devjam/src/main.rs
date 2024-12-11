use anyhow::{Context as _, Ok};
use chrono::{self};
use std::sync::Arc;
use std::{ptr, slice};
use warp::Filter;
use warp_handlers::{get_universe, with_universe};

use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
use log::{debug, info, warn};
use tokio::io::unix::AsyncFd;
use tokio::join;
use tokio::sync::{mpsc, watch, RwLock};

mod structs;
mod warp_handlers;
use structs::{DnsResponse, MyResourceRecord};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp5s0")]
    iface: String,
}

async fn event_collector<'a>(
    mut rx: mpsc::Receiver<DnsResponse<'a>>,
    received_data: Arc<RwLock<Vec<DnsResponse<'a>>>>,
) {
    info!("Started event collector");
    while let Some(value) = rx.recv().await {
        // Acquire a write lock to modify the received_data
        let mut data = received_data.write().await;
        data.push(value);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
    let ring_dump =
        aya::maps::RingBuf::try_from(ebpf.take_map("DNS_RESPONSES_RING_BUFFER").unwrap()).unwrap();

    let (_tx, rx) = watch::channel(false);
    let (t_event, r_event_collector): (mpsc::Sender<DnsResponse>, mpsc::Receiver<DnsResponse>) =
        mpsc::channel(50);

    let received_data = Arc::new(RwLock::new(Vec::new()));

    let read_buffer = tokio::spawn(async move {
        let mut rx = rx.clone();
        let t_event = t_event.clone();
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

                        // relevant commets below, cause there is some code
                        let mut _timestamp = unsafe { ptr::read_unaligned::<u64>(ptr.byte_add(2) as *const u64) };
                        // checking for timestamp diff, as the timestamp that is read from the DNS_RESPONSES_RING_BUFFER is the timestamp since boot time, so we would need some magic to actually convert this
                        // but, my testing on a usual load indicates this is at max < 100 ms, so we are fine, for PoC for sure
                        // thus we will be concating userspace time when this was read from ring buffer
                        // dbg!(&timestamp);
                        // timestamp = u64::MAX - timestamp.wrapping_sub(std::time::Duration::from(nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC).unwrap()).as_nanos() as u64);

                        let data = unsafe { slice::from_raw_parts(ptr.byte_add(2).byte_add(8), size.into()) };
                        let reading_time = chrono::offset::Utc::now();

                        if let std::result::Result::Ok(response_packet) = dns_parser::Packet::parse(&data[42_usize..size as usize]) {
                            let my_records: Vec<MyResourceRecord> = response_packet.answers.into_iter().map(MyResourceRecord).collect();
                            t_event.send((my_records, reading_time)).await.unwrap();
                        }
                        else{
                            // Now this is the funny part I do not understand, thing is, if for some reason header is extended
                            // it does not start at start + 42, so we need to bruteforce find where the actual packet starts that
                            // is parsable, consider exposing this as metric if this project ever expands
                            for i in 0..size {
                                match dns_parser::Packet::parse(&data[i as usize..size as usize]) {
                                    Err(_) => {},
                                 std::result::Result::Ok(response_packet) => {
                                    let my_records: Vec<MyResourceRecord> = response_packet.answers.into_iter().map(MyResourceRecord).collect();
                                    t_event.send((my_records, reading_time)).await.unwrap();
                                break;
                                },
                            }
                            }
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
        let received_data = Arc::clone(&received_data);
        tokio::spawn(async move {
            event_collector(r_event_collector, received_data).await;
        })
    };
    let get_universe_route = warp::path("universe")
        .and(warp::get())
        .and(with_universe(received_data.clone()))
        .and_then(get_universe);

    let warp_handle = {
        tokio::spawn(async move {
            warp::serve(get_universe_route)
                .run(([127, 0, 0, 1], 3030))
                .await;
        })
    };

    join!(collector, read_buffer, warp_handle);
    info!("Exiting...");
    Ok(())
}
