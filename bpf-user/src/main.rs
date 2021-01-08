use redbpf::xdp::Flags;
use redbpf::Program::*;
use redbpf::{load::Loader, HashMap as BPFHashMap};
use simple_logger::SimpleLogger;
use std::env;
use std::io;
use std::io::prelude::*;
use std::net::TcpStream;
use std::path::Path;
use std::process;
use std::time::Duration;
use tokio::signal;
use tokio::time::delay_for;

pub mod aggs;
pub mod elastic_mapping;
pub mod network_utils;

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    // Initialize the logger to support a certain debug level.
    SimpleLogger::new()
        .with_level(log::LevelFilter::Debug)
        .init()
        .unwrap();

    // let args: Vec<String> = env::args().collect(); // ARGV

    // check for args length
    // if args.len() != 3 {
    //     log::error!("usage: bpf-user [NETWORK_INTERFACE] [FILENAME]");
    //     return Err(io::Error::new(io::ErrorKind::Other, "invalid arguments"));
    // }

    // // Load all of the XDP programs from the binary
    // for program in loader.module.programs.iter_mut() {
    //     let name = program.name().to_string();
    //     let _ret = match program {
    //         XDP(prog) => {
    //             log::info!("Attaching to {:?} interface: {:?}", &name, &interface);
    //             prog.attach_xdp(&interface, Flags::default()) // attach the program to the Kernel space
    //         },
    //         _ => Ok(()),
    //     };
    // }

    let mut loaded = Loader::load(probe_code()).expect("Error loading BPF program");
    for kp in loaded.kprobes_mut() {
        kp.attach_kprobe(&kp.name(), 0)
            .expect(&format!("error attaching kprobe program {}", kp.name()));
    }

    log::info!("Trying to establish socket connection to logstash");
    let mut socket_connection = match TcpStream::connect("localhost:5000") {
        Ok(con) => {
            log::info!("Connected to logstash successfully");
            con
        }
        Err(_) => {
            log::error!("Connection to logstash failed, aborting.");
            process::exit(1);
        }
    };

    // Listen to incoming map's data
    tokio::spawn(async move {
        let download_ips =
            BPFHashMap::<u32, aggs::IPAggs>::new(loaded.map("download_ip_map").unwrap()).unwrap();
        let download_ports =
            BPFHashMap::<u16, aggs::PortAggs>::new(loaded.map("download_port_map").unwrap())
                .unwrap();
        let upload_ips =
            BPFHashMap::<u32, aggs::IPAggs>::new(loaded.map("upload_ip_map").unwrap()).unwrap();
        let upload_ports =
            BPFHashMap::<u16, aggs::PortAggs>::new(loaded.map("upload_port_map").unwrap())
                .unwrap();
        loop {
            delay_for(Duration::from_millis(15000)).await;
            //format ips Hashmap into vec
            let download_ip_vec: Vec<(u32, aggs::IPAggs)> = download_ips.iter().collect();
            let upload_ip_vec: Vec<(u32, aggs::IPAggs)> = upload_ips.iter().collect();

            let mut parsed_ips: Vec<elastic_mapping::EsReadyIpAggs> = Vec::new();
            let mut packet_count: u32 = 0;

            log::debug!("========ip addresses=======");

            for (k, v) in download_ip_vec.iter().rev() {
                log::debug!(
                    "{:?} - > count:{:?}",
                    network_utils::u32_to_ipv4(*k),
                    v.count
                );

                let current_ip_agg = elastic_mapping::EsReadyIpAggs {
                    ip: network_utils::u32_to_ipv4(*k).to_string(),
                    count: v.count,
                    usage: v.usage,
                };

                packet_count += v.count;
                parsed_ips.push(current_ip_agg);
                download_ips.delete(*k);
            }

            for (k, v) in upload_ip_vec.iter().rev() {
                log::debug!(
                    "{:?} - > count:{:?}",
                    network_utils::u32_to_ipv4(*k),
                    v.count
                );

                let current_ip_agg = elastic_mapping::EsReadyIpAggs {
                    ip: network_utils::u32_to_ipv4(*k).to_string(),
                    count: v.count,
                    usage: v.usage,
                };

                packet_count += v.count;
                parsed_ips.push(current_ip_agg);
                upload_ips.delete(*k);
            }

            //format port Hashmap into vec
            let download_port_vec: Vec<(u16, aggs::PortAggs)> = download_ports.iter().collect();
            let upload_port_vec: Vec<(u16, aggs::PortAggs)> = upload_ports.iter().collect();
            let mut parsed_ports: Vec<elastic_mapping::EsReadyPortAggs> = Vec::new();

            log::debug!("========ports=======");

            for (k, v) in download_port_vec.iter().rev() {
                log::debug!("{:?} - > count:{:?}", k, v.count);
                let current_port_agg = elastic_mapping::EsReadyPortAggs {
                    port: *k,
                    count: v.count,
                };

                parsed_ports.push(current_port_agg);
                download_ports.delete(*k);
            }

            for (k, v) in upload_port_vec.iter().rev() {
                log::debug!("{:?} - > count:{:?}", k, v.count);
                let current_port_agg = elastic_mapping::EsReadyPortAggs {
                    port: *k,
                    count: v.count,
                };

                parsed_ports.push(current_port_agg);
                upload_ports.delete(*k);
            }

            let data_iteration = elastic_mapping::BPFDataIteration {
                ips: parsed_ips,
                ports: parsed_ports,
                packet_count,
            };

            let msg = socket_connection.write(
                &format!("{}\n", &serde_json::to_string(&data_iteration).unwrap()).as_bytes(),
            );
            match msg {
                Err(_) => {
                    log::error!("Broken pipe! [Possibly lost connection to server] aborting.");
                    process::exit(1);
                }
                _ => {
                    log::info!("Sent data iteration successfully");
                }
            }
        }
    });
    signal::ctrl_c().await
}

fn probe_code() -> &'static [u8] {
    include_bytes!("../../bpf-kernel/target/bpf/programs/monitor/monitor.elf")
}
