extern crate procfs;


fn main() {
    let mut args = std::env::args();
    args.next();
    let pid = i32::from_str_radix(&args.next().unwrap(), 10).unwrap();

    println!("Info for pid={}", pid);
    let proc = procfs::Proc::new(pid).unwrap();
    println!("{:#?}", proc);

    println!("State: {:?}", proc.stat.state());
    println!("RSS:   {} bytes", proc.stat.rss_bytes());
}
