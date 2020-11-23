// aggs => aggregations 
use redbpf::Program::*;
use serde::{Deserialize, Serialize};

#[repr(C)]
#[derive(Debug, Clone)]
#[derive(Serialize, Deserialize)]

pub struct PortAggs {
    pub count: u32,
}

#[repr(C)]
#[derive(Debug, Clone)]
#[derive(Serialize, Deserialize)]
pub struct IPAggs {
    pub count: u32,
    pub usage: u32, // bits
    // pub packet_count: u32
}