extern crate procfs;

fn main() {

    let pid = std::env::args().nth(1).and_then(|s| i32::from_str_radix(&s, 10).ok());

    let prc = if let Some(pid) = pid {
        println!("Info for pid={}", pid);
        procfs::Process::new(pid).unwrap()
    } else {
        procfs::Process::myself().unwrap()
    };
    println!("{:#?}", prc);

    println!("State: {:?}", prc.stat.state());
    println!("RSS:   {} bytes", prc.stat.rss_bytes());
}
