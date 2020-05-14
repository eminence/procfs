

#[cfg(test)]
mod tests {
    extern crate failure;
        /// Test that our error type can be easily used with the `failure` crate
        #[test]
        fn test_failure() {
            fn inner() -> Result<(), failure::Error> {
                let _load = procfs::LoadAverage::new()?;
                Ok(())
            }
            let _ = inner();
    
            fn inner2() -> Result<(), failure::Error> {
                let proc = procfs::process::Process::new(1)?;
                let _io = proc.maps()?;
                Ok(())
            }
    
            let _ = inner2();
            // Unwrapping this failure should produce a message that looks like:
            // thread 'tests::test_failure' panicked at 'called `Result::unwrap()` on an `Err` value: PermissionDenied(Some("/proc/1/maps"))', src/libcore/result.rs:997:5
        }
}
