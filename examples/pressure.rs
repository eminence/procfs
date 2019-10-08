/// A basic example of /proc/pressure/ usage.

fn main() {
    println!("memory pressure: {:#?}", procfs::memory_pressure());
    println!("cpu pressure: {:#?}", procfs::cpu_pressure());
    println!("io pressure: {:#?}", procfs::io_pressure());
}
