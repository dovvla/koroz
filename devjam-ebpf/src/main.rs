#![no_std]
#![no_main]

use core::{mem, ptr, usize};

use aya_ebpf::{
    bindings::xdp_action::{self, XDP_PASS},
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::RingBuf,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[map]
static DNS_RESPONSES_RING_BUFFER: RingBuf = RingBuf::with_byte_size(16_777_216u32, 0);

#[xdp]
pub fn devjam(ctx: XdpContext) -> u32 {
    match try_devjam(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}

fn try_devjam(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {
            let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN) }?;

            match unsafe { (*ipv4hdr).proto } {
                IpProto::Tcp => {
                    return Ok(XDP_PASS);
                }
                IpProto::Udp => {
                    let udphdr: *const UdpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
                    if u16::from_be(unsafe { (*udphdr).source }) != 53 {
                        return Ok(XDP_PASS);
                    }
                }
                _ => return Err(()),
            };
        }
        _ => return Ok(xdp_action::XDP_PASS),
    }

    const U16_SIZE: usize = mem::size_of::<u16>();
    const U64_SIZE: usize = mem::size_of::<u64>();
    const SIZE: usize = U16_SIZE + U64_SIZE + 1500;

    match DNS_RESPONSES_RING_BUFFER.reserve::<[u8; SIZE]>(0) {
        Some(mut event) => {
            let len = ctx.data_end() - ctx.data();

            if aya_ebpf::check_bounds_signed(len as i64, 1, 1500) == false {
                event.discard(0);
                return Ok(xdp_action::XDP_PASS);
            }

            unsafe {
                ptr::write_unaligned(event.as_mut_ptr() as *mut _, len as u16);
                let now = bpf_ktime_get_ns();
                ptr::write_unaligned(event.as_mut_ptr().byte_add(U16_SIZE) as *mut _, now);

                match aya_ebpf::helpers::gen::bpf_xdp_load_bytes(
                    ctx.ctx,
                    0,
                    event.as_mut_ptr().byte_add(U16_SIZE).byte_add(U64_SIZE) as *mut _,
                    len as u32,
                ) {
                    0 => event.submit(0),
                    _ => event.discard(0),
                }
            }
        }
        None => {
            info!(&ctx, "Cannot reserve space in ring buffer.");
        }
    };
    return Ok(XDP_PASS);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
