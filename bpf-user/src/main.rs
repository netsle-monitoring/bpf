use futures::{future, stream::StreamExt};
use redbpf::load::Loader;
use redbpf::xdp::{Flags, MapData};
use redbpf::Program::*;
use std::env;
use std::io;
use std::path::Path;
use tokio::signal;

pub mod network_utils;

// The event map (the data structure we pass through the stream/maps)
#[repr(C)]
#[derive(Debug)]
pub struct Event {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
}

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

    let mut loader = Loader::load_file(&Path::new(&file)).expect("Error loading file...");

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
        let mut packet_num: u32 = 0;
        while let Some((_name, events)) = loader.events.next().await {
            for event in events {
                //let structured_event = unsafe { std::ptr::read(event.as_ptr() as *const Event) };
                let data = unsafe { &*(event.as_ptr() as *const MapData<Event>) };
                let structured_event = data.data();
                packet_num += 1;
                println!(
                    "{:?}:{:?} -> {:?}:{:?} length: {:?} #{}",
                    network_utils::u32_to_ipv4(structured_event.saddr),
                    structured_event.sport,
                    network_utils::u32_to_ipv4(structured_event.daddr),
                    structured_event.dport,
                    data.payload().len(),
					packet_num
                );
                //println!("{:?}", to_ipv4(structuredEvent.daddr))
            }
        }

        // If the program doesn't have any maps and therefore doesn't fire any events, we still
        // need to keep `loader` alive here so that BPF programs are not dropped. The future
        // below will never complete, meaning that the programs will keep running until Ctrl-C
        future::pending::<()>().await;
    });

    signal::ctrl_c().await
}
