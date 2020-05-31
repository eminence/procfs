use crate::{read_value, ProcResult};

pub fn enabled() -> ProcResult<bool> {
    let val: String = read_value("/proc/sys/fs/binfmt_misc/status")?;
    Ok(val == "enabled")
}

pub struct BinFmtEntry {
    pub enabled: bool,
    pub interpreter: String,
    pub flags: (),
    pub offset: u8,
    pub magic: Vec<u8>,
}

#[cfg(test)]
mod tests {
    #[test]
    fn enabled() {
        println!("{}", super::enabled().unwrap());
    }
}
