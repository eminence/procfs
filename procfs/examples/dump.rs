extern crate procfs;
use procfs::prelude::*;

fn main() {
    let pid = std::env::args().nth(1).and_then(|s| s.parse::<i32>().ok());

    let prc = if let Some(pid) = pid {
        println!("Info for pid={}", pid);
        procfs::process::Process::new(pid).unwrap()
    } else {
        procfs::process::Process::myself().unwrap()
    };
    println!("{:#?}", prc);

    let stat = prc.stat().unwrap();
    println!("State: {:?}", stat.state());
    println!("RSS:   {} bytes", stat.rss_bytes().get());
}
