fn main() {
    // Filters are extracted from `libc` filters
    #[cfg(not(any(
        target_os = "android",
        target_os = "linux", target_os = "l4re",
    )))]
    compile_error!("Building procfs on an for a unsupported platform. Currently only linux and android are supported")
}
