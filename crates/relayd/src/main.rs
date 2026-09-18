//! The relay daemon.
//!
//! ```text
//! onestein-relayd [--listen ADDRESS]
//! ```
//!
//! Defaults to 127.0.0.1:0, which prints the port it took and serves only the
//! machine it runs on. A relay meant for other people is put behind Tor or a
//! reverse proxy by whoever runs it; this program does not open itself to the
//! world by accident.

use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use onestein_relayd::{Shared, serve};

fn main() -> std::process::ExitCode {
    let mut address = "127.0.0.1:0".to_owned();
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--listen" => match arguments.next() {
                Some(value) => address = value,
                None => {
                    eprintln!("--listen needs an address");
                    return std::process::ExitCode::from(2);
                }
            },
            "--help" | "-h" => {
                println!("onestein-relayd [--listen ADDRESS]");
                return std::process::ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument: {other}");
                return std::process::ExitCode::from(2);
            }
        }
    }

    let listener = match TcpListener::bind(&address) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("cannot listen on {address}: {error}");
            return std::process::ExitCode::from(1);
        }
    };
    match listener.local_addr() {
        Ok(bound) => println!("listening on {bound}"),
        Err(error) => eprintln!("listening, but cannot name the address: {error}"),
    }

    serve(&listener, &Arc::new(Mutex::new(Shared::new())));
    std::process::ExitCode::SUCCESS
}
