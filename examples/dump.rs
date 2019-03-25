extern crate procfs;

fn main() {
    let pid = i32::from_str_radix(
        &std::env::args().nth(1).expect("no proc ID arg specified"),
        10,
    )
    .unwrap();

    println!("Info for pid={}", pid);
    let prc = procfs::Process::new(pid).unwrap();
    println!("{:#?}", prc);

    println!("State: {:?}", prc.stat.state());
    println!("RSS:   {} bytes", prc.stat.rss_bytes());
}
