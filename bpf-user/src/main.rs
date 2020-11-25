use redbpf::xdp::{Flags};
use redbpf::Program::*;
use std::env;
use std::io;
use std::path::Path;
use tokio::signal;
use tokio::time::delay_for;
use std::time::Duration;

use redbpf::{load::Loader, HashMap as BPFHashMap};

pub mod network_utils;
pub mod aggs;

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let args: Vec<String> = env::args().collect(); // ARGV

    // check for args length
    if args.len() != 3 {
        eprintln!("usage: bpf_example_program [NETWORK_INTERFACE] [FILENAME]");
        return Err(io::Error::new(io::ErrorKind::Other, "invalid arguments"));
    }

    let interface = args[1].clone();
    let file = args[2].clone();

    let mut  loader = Loader::load_file(&Path::new(&file)).expect("Error loading file...");

    // Load all of the XDP programs from the binary 
    for program in loader.module.programs.iter_mut() {
        let name = program.name().to_string();
        let _ret = match program {
            XDP(prog) => {
                println!("Attaching to {:?} interface: {:?}!!!", &name, &interface);
                prog.attach_xdp(&interface, Flags::default()) // attach the program to the Kernel space
            }
            _ => Ok(()),
        };
    }

    // Listen to incoming map's data
    tokio::spawn(async move {
        let ips =
            BPFHashMap::<u32, aggs::IPAggs>::new(loader.map("ip_map").unwrap()).unwrap();
        let ports = 
            BPFHashMap::<u16, aggs::PortAggs>::new(loader.map("port_map").unwrap()).unwrap();

        loop {
            delay_for(Duration::from_millis(1000)).await;
            //format ips Hashmap into vec
            let  ip_vec: Vec<(u32, aggs::IPAggs)> = ips.iter().collect();
            println!("========Ips=======");
            for (k, v) in ip_vec.iter().rev() {
                println!(
                    "{:?} - > count:{:?}",
                    network_utils::u32_to_ipv4(*k),
                    v.count
                );
                ips.delete(*k);
            }

            //format port Hashmap into vec
            let  port_vec: Vec<(u16, aggs::PortAggs)> = ports.iter().collect();
            println!("========Ports=======");
            for (k, v) in port_vec.iter().rev() {
                println!(
                    "{:?} - > count:{:?}",
                    k,
                    v.count
                );
                ports.delete(*k);
            }
        }
    });
    signal::ctrl_c().await
}
