use serde::{Deserialize, Serialize};
// aggs => aggregations
#[repr(C)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PortAggs {
    pub count: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug)]
pub enum Direction {
    Upload,
    Download
}