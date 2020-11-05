use crate::{read_value, ProcResult};

/// Returns true if the miscellaneous Binary Formats system is enabled.
pub fn enabled() -> ProcResult<bool> {
    let val: String = read_value("/proc/sys/fs/binfmt_misc/status")?;
    Ok(val == "enabled")
}

/*
struct BinFmtEntry {
    pub enabled: bool,
    pub interpreter: String,
    pub flags: (),
    pub offset: u8,
    pub magic: Vec<u8>,
}
*/

#[cfg(test)]
mod tests {
    #[test]
    fn enabled() {
        match super::enabled() {
            Ok(_) => {}
            Err(crate::ProcError::NotFound(_)) => {}
            Err(e) => panic!("{}", e),
        }
    }
}
