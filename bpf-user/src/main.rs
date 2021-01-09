use redbpf::{load::Loaded, load::Loader};
use simple_logger::SimpleLogger;
// use std::io::prelude::*;
use std::net::TcpStream;
use std::process;
// use std::time::Duration;
use tokio::signal;
// use tokio::time::delay_for;
use futures::stream::StreamExt;
use std::ptr;
use tokio::runtime::Runtime;

pub mod aggs;
pub mod elastic_mapping;
pub mod network_utils;

fn main() {
    // Initialize the logger to support a certain debug level.
    SimpleLogger::new()
        .with_level(log::LevelFilter::Debug)
        .init()
        .unwrap();
    let _ = Runtime::new().unwrap().block_on(async {
        let mut loaded = Loader::load(probe_code()).expect("error loading BPF program");
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

        start_perf_event_handler(loaded, &mut socket_connection);

        signal::ctrl_c().await
    });

    // Listen to incoming map's data
}

fn probe_code() -> &'static [u8] {
    include_bytes!("../../bpf-kernel/target/bpf/programs/monitor/monitor.elf")
}

fn start_perf_event_handler(mut loaded: Loaded, mut _connection: &TcpStream) {
    tokio::spawn(async move {
        while let Some((name, events)) = loaded.events.next().await {
            for event in events {
                match name.as_str() {
                    "ip_volumes" => {
                        let message = unsafe { ptr::read(event.as_ptr() as *const aggs::Message) };
                        let (direction, conn, vol) = match message {
                            aggs::Message::Send(c, l) => (aggs::Direction::Upload, c, l),
                            aggs::Message::Receive(c, l) => (aggs::Direction::Download, c, l),
                        };

                        let sourceip = network_utils::u32_to_ipv4(conn.saddr).to_string();
                        match direction {
                            aggs::Direction::Download => {
                                if sourceip != "127.0.0.1" {
                                    println!(
                                        "GOT VOLUME ({:?}) {}:{} -> {}:{} VOLUMES => {:?}",
                                        direction,
                                        sourceip,
                                        conn.sport,
                                        network_utils::u32_to_ipv4(conn.daddr).to_string(),
                                        conn.dport,
                                        vol
                                    );
                                }
                            }
                            _ => {},
                        }
                    }
                    _ => {},
                }
            }
        }
    });
}
