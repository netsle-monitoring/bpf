#![no_std]
#![no_main]
use redbpf_probes::xdp::prelude::*;

pub mod aggs;

program!(0xFFFFFFFE, "GPL");

// A macro which defines an insert behavior
// If there isn't a key, create an entry
// if there is a key, return the entry
macro_rules! insert_to_map {
    ($map:expr, $key:expr, $agg_to_insert:expr) => {
        match $map.get_mut($key) {
            Some(c) => c,
            None => {
                $map.set($key, $agg_to_insert);
                $map.get_mut($key).unwrap()
            }
        }
    }
}

#[map("ip_map")]
static mut ip_map: HashMap<u32, aggs::IPAggs> = HashMap::with_max_entries(10240);
#[map("port_map")]
static mut port_map: HashMap<u16, aggs::PortAggs> = HashMap::with_max_entries(10240);
#[map("ip_blacklist")]
static mut ip_blacklist: HashMap<u32, u32> = HashMap::with_max_entries(10240);

#[xdp("monitor")]
pub fn probe(ctx: XdpContext) -> XdpResult {
    let ip = unsafe { *ctx.ip()? };
    let transport = ctx.transport()?;
    let data = ctx.data()?;
    
    if unsafe {ip_blacklist.get(&ip.saddr).is_some()} {
        return Ok(XdpAction::Drop)
    }

    let port_agg = aggs::PortAggs {
        count: 0u32
    };
    
    let ip_agg = aggs::IPAggs {
        count: 0u32,
        usage: 0u32, // bits
    };

    unsafe {
        let mut port_agg_sport = insert_to_map!(port_map, &transport.source(), &port_agg);
        let mut port_agg_dport = insert_to_map!(port_map, &transport.dest(), &port_agg);
        let mut ip_agg_sip = insert_to_map!(ip_map, &ip.saddr, &ip_agg);
        let mut ip_agg_dip = insert_to_map!(ip_map, &ip.daddr, &ip_agg);
        
        ip_agg_dip.count += 1;
        ip_agg_sip.count += 1;
        ip_agg_sip.usage += data.len() as u32 + data.offset() as u32;
        ip_agg_dip.usage += data.len() as u32 + data.offset() as u32;

        port_agg_sport.count += 1;
        port_agg_dport.count += 1;
    };
    
    Ok(XdpAction::Pass)
}
