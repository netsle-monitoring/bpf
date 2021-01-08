// #[repr(C)]
// pub struct Ipv4Addr(in4_addr);

// impl From<in4_addr> for Ipv4Addr {
//     #[inline]
//     fn from(src: in4_addr) -> IpV4Addr {
//         Ipv4Addr(src)
//     }
// }

// aggs => aggregations 
#[repr(C)]
#[derive(Debug, Clone)]
pub struct PortAggs {
    pub count: u32,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct IPAggs {
    pub count: u32,
    pub usage: u32, // bits
    // pub packet_count: u32
}

#[derive(Debug)]
pub struct Connection {
    pub sport: u16,
    pub dport: u16,
    pub saddr: u32,
    pub daddr: u32,
}

#[derive(Debug)]
pub enum Message {
    Receive(Connection, u16),
    Send(Connection, u16),
}