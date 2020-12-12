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
