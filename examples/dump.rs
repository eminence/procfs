extern crate procfs;

fn main() {
    let mut args = std::env::args();
    args.next();
    let pid = i32::from_str_radix(&args.next().unwrap(), 10).unwrap();

    println!("Info for pid={}", pid);
    let prc = procfs::Process::new(pid).unwrap();
    println!("{:#?}", prc);

    println!("State: {:?}", prc.stat.state());
    println!("RSS:   {} bytes", prc.stat.rss_bytes());
}
