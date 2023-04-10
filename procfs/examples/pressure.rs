use procfs::prelude::*;

/// A basic example of /proc/pressure/ usage.
fn main() {
    println!("memory pressure: {:#?}", procfs::MemoryPressure::current());
    println!("cpu pressure: {:#?}", procfs::CpuPressure::current());
    println!("io pressure: {:#?}", procfs::IoPressure::current());
}
