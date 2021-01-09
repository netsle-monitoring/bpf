#![no_std]
#![no_main]
// use redbpf_probes::xdp::prelude::*;
use redbpf_probes::kprobe::prelude::*;
pub mod aggs;
program!(0xFFFFFFFE, "GPL");

#[map("task_to_socket")]
static mut task_to_socket: HashMap<u64, *const sock> = HashMap::with_max_entries(10240);
#[map("ip_volumes")]
static mut ip_volumes: PerfMap<aggs::Message> = PerfMap::with_max_entries(1024); 
#[map("ip_connections")]
static mut ip_connections: PerfMap<aggs::Connection> = PerfMap::with_max_entries(1024);

#[kprobe("tcp_v4_connect")]
pub fn connect_enter(regs: Registers) {
    store_socket(regs)
}

#[kretprobe("tcp_v4_connect")]
pub fn connect(regs: Registers) {
    if let Some(c) = conn_details(regs) {
        unsafe {
            ip_connections.insert(regs.ctx, &c);
        }
    }
}

#[kprobe("tcp_sendmsg")]
pub fn send_enter(regs: Registers) {
    store_socket(regs)
}

#[kretprobe("tcp_sendmsg")]
pub fn send_exit(regs: Registers) {
    trace_message(regs, aggs::Message::Send)
}

#[kprobe("tcp_recvmsg")]
pub fn recv_enter(regs: Registers) {
    store_socket(regs)
}

#[kretprobe("tcp_recvmsg")]
pub fn recv_exit(regs: Registers) {
    trace_message(regs, aggs::Message::Receive)
}

#[kprobe("udp_sendmsg")]
pub fn udp_send_enter(regs: Registers) {
    trace_message(regs, aggs::Message::Send)
}

#[kprobe("udp_rcv")]
pub fn udp_rcv_enter(regs: Registers) {
    trace_message(regs, aggs::Message::Receive)
}

#[inline(always)]
fn store_socket(regs: Registers) {
    unsafe { task_to_socket.set(&bpf_get_current_pid_tgid(), &(regs.parm1() as *const sock)) };
}

#[inline(always)]
fn trace_message(regs: Registers, direction: fn(aggs::Connection, u16) -> aggs::Message) {
    if let Some(c) = conn_details(regs) {
        let len = regs.parm3() as u16;
        unsafe {
            ip_volumes.insert(regs.ctx, &direction(c, len));
        }
    }
}

#[inline(always)]
pub fn conn_details(_regs: Registers) -> Option<aggs::Connection> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let socket = unsafe {
        match task_to_socket.get(&pid_tgid) {
            Some(s) => &**s,
            None => return None,
        }
    };

    let family = socket.skc_family()?;

    if family as u32 == AF_INET6 {
        return None;
    }

    let dest = socket.skc_daddr()?;
    let src = socket.skc_rcv_saddr()?;

    let dport = socket.skc_dport()? as u16;
    let sport = socket.skc_num()? as u16;

    unsafe {
        task_to_socket.delete(&pid_tgid);
    }

    Some(aggs::Connection {
        saddr: src as u32,
        daddr: dest as u32,
        sport,
        dport,
    })
}

// #[xdp("monitor")]
// pub fn probe(ctx: XdpContext) -> XdpResult {
//     let ip = unsafe { *ctx.ip()? };
//     let transport = ctx.transport()?;
//     let data = ctx.data()?;
//     unsafe {
//         let mut port_agg_sport = insert_to_map!(port_map, &transport.source(), &port_agg);
//         let mut port_agg_dport = insert_to_map!(port_map, &transport.dest(), &port_agg);
//         let mut ip_agg_sip = insert_to_map!(ip_map, &ip.saddr, &ip_agg);
//         let mut ip_agg_dip = insert_to_map!(ip_map, &ip.daddr, &ip_agg);
//         ip_agg_dip.count += 1;
//         ip_agg_sip.count += 1;
//         ip_agg_sip.usage += data.len() as u32 + data.offset() as u32;
//         ip_agg_dip.usage += data.len() as u32 + data.offset() as u32;

//         port_agg_sport.count += 1;
//         port_agg_dport.count += 1;
//     };
//     Ok(XdpAction::Pass)
// }
