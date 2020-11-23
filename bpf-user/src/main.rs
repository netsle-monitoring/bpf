use futures::{future, stream::StreamExt};
use redbpf::load::Loader;
use redbpf::xdp::{Flags, MapData};
use redbpf::Program::*;
use std::env;
use std::io;
use std::path::Path;
use tokio::signal;
use tokio::time::delay_for;
use std::time::Duration;

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
        loop {
            delay_for(Duration::from_millis(1000)).await;
        }

        // If the program doesn't have any maps and therefore doesn't fire any events, we still
        // need to keep `loader` alive here so that BPF programs are not dropped. The future
        // below will never complete, meaning that the programs will keep running until Ctrl-C
        future::pending::<()>().await;
    });

    signal::ctrl_c().await
}
