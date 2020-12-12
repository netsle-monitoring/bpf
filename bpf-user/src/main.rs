use redbpf::xdp::Flags;
use redbpf::Program::*;
use std::env;
use std::io;
use std::path::Path;
use std::time::Duration;
use tokio::signal;
use tokio::time::delay_for;
use std::net::{TcpStream};
use redbpf::{load::Loader, HashMap as BPFHashMap};
use std::io::prelude::*;
use simple_logger::SimpleLogger;
use std::process;

pub mod aggs;
pub mod network_utils;
pub mod elastic_mapping;

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    // Initialize the logger to support a certain debug level.
    SimpleLogger::new().with_level(log::LevelFilter::Debug).init().unwrap();

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
        },
        Err(_) => {
            log::error!("Connection to logstash failed, aborting.");
            process::exit(1);
        }
    };


    // Listen to incoming map's data
    tokio::spawn(async move {
        let ips = BPFHashMap::<u32, aggs::IPAggs>::new(loader.map("ip_map").unwrap()).unwrap();
        let ports =
            BPFHashMap::<u16, aggs::PortAggs>::new(loader.map("port_map").unwrap()).unwrap();

        loop {
            delay_for(Duration::from_millis(60000)).await;
            //format ips Hashmap into vec
            let ip_vec: Vec<(u32, aggs::IPAggs)> = ips.iter().collect();
            let mut parsed_ips: Vec<elastic_mapping::EsReadyIpAggs> = Vec::new();

            log::debug!("========ip addresses=======");
            for (k, v) in ip_vec.iter().rev() {
                log::debug!(
                    "{:?} - > count:{:?}",
                    network_utils::u32_to_ipv4(*k),
                    v.count
                );
                
                let current_ip_agg = elastic_mapping::EsReadyIpAggs {
                    ip: network_utils::u32_to_ipv4(*k).to_string(),
                    count: v.count,
                    usage: v.usage
                };

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
            };

            socket_connection.write(&format!("{}\n", &serde_json::to_string(&data_iteration).unwrap()).as_bytes()).unwrap();
        }
    });
    signal::ctrl_c().await
}
