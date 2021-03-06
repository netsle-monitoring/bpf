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

    let args: Vec<String> = env::args().collect(); // ARGV

    // check for args length
    if args.len() != 3 {
        log::error!("usage: bpf-user [NETWORK_INTERFACE] [FILENAME]");
        return Err(io::Error::new(io::ErrorKind::Other, "invalid arguments"));
    }

    let interface = args[1].clone();
    let file = args[2].clone();

    let mut loader = Loader::load_file(&Path::new(&file)).expect("Error loading file...");

    // Load all of the XDP programs from the binary
    for program in loader.module.programs.iter_mut() {
        let name = program.name().to_string();
        let _ret = match program {
            XDP(prog) => {
                log::info!("Attaching to {:?} interface: {:?}", &name, &interface);
                prog.attach_xdp(&interface, Flags::default()) // attach the program to the Kernel space
            }
            _ => Ok(()),
        };
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

    use std::net::Ipv4Addr;
    let ip = Ipv4Addr::new(212, 25, 76, 101).octets();

    // Listen to incoming map's data
    tokio::spawn(async move {
        let blacklist = BPFHashMap::<u32, u32>::new(loader.map("ip_blacklist").unwrap()).unwrap();
        let ips = BPFHashMap::<u32, aggs::IPAggs>::new(loader.map("ip_map").unwrap()).unwrap();
        let ports =
            BPFHashMap::<u16, aggs::PortAggs>::new(loader.map("port_map").unwrap()).unwrap();
        loop {
            match reqwest::blocking::get("http://localhost:8000/admin/blacklist") {
                Err(_) => {}
                Ok(r) => {
                    let json: Vec<String> = r.json().unwrap();
                    let blacklist_vec: Vec<(u32, u32)> = blacklist.iter().collect();
                    for (k, _) in blacklist_vec.iter().rev() {
                        blacklist.delete(*k);
                    }

                    for ip in json {
                        let asu32 = network_utils::ipv4_to_u32(
                            ip.parse::<Ipv4Addr>().unwrap().octets().to_vec(),
                        );

                        blacklist.set(asu32, asu32)
                    }
                }
            }

            // .json()
            // .unwrap();

            delay_for(Duration::from_millis(60000)).await;
            //format ips Hashmap into vec
            let ip_vec: Vec<(u32, aggs::IPAggs)> = ips.iter().collect();
            let mut parsed_ips: Vec<elastic_mapping::EsReadyIpAggs> = Vec::new();
            let mut packet_count: u32 = 0;
            log::debug!("========ip addresses=======");
            for (k, v) in ip_vec.iter().rev() {
                log::debug!(
                    "{:?} {:?} - > count:{:?}",
                    network_utils::u32_to_ipv4(*k),
                    *k,
                    v.count
                );
                let current_ip_agg = elastic_mapping::EsReadyIpAggs {
                    ip: network_utils::u32_to_ipv4(*k).to_string(),
                    count: v.count,
                    usage: v.usage,
                };
                packet_count += v.count;
                parsed_ips.push(current_ip_agg);
                ips.delete(*k);
            }
            //format port Hashmap into vec
            let port_vec: Vec<(u16, aggs::PortAggs)> = ports.iter().collect();
            let mut parsed_ports: Vec<elastic_mapping::EsReadyPortAggs> = Vec::new();
            log::debug!("========ports=======");
            for (k, v) in port_vec.iter().rev() {
                log::debug!("{:?} - > count:{:?}", k, v.count);
                let current_port_agg = elastic_mapping::EsReadyPortAggs {
                    port: *k,
                    count: v.count,
                };
                parsed_ports.push(current_port_agg);
                ports.delete(*k);
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
