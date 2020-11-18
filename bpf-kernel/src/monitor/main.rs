
#![no_std]
#![no_main]
use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[repr(C)]
pub struct Packet {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
}

#[map("events")]
static mut packets: PerfMap<Packet> = PerfMap::with_max_entries(1024);

#[xdp("monitor")]
pub fn probe(ctx: XdpContext) -> XdpResult {
    let ip = unsafe { *ctx.ip()? };
    let transport = ctx.transport()?;
    let data = ctx.data()?;

    let packet = Packet {
        saddr: ip.saddr,
        daddr: ip.daddr,
        sport: transport.source(),
        dport: transport.dest(),
    };

    unsafe {
        packets.insert(
            &ctx,
            &MapData::with_payload(packet, data.offset() as u32, ctx.len() as u32),
        )
    };

    Ok(XdpAction::Pass)
}