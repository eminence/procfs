/// A basic example of /proc/pressure/ usage.

#[cfg(not(feature = "parsing_only"))]
fn main() {
    println!("memory pressure: {:#?}", procfs::MemoryPressure::new());
    println!("cpu pressure: {:#?}", procfs::CpuPressure::new());
    println!("io pressure: {:#?}", procfs::IoPressure::new());
}

#[cfg(feature = "parsing_only")]
fn main() {
    println!("This example must be run on linux");
}
