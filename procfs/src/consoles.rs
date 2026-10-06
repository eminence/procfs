use super::{Current, ProcResult};
pub use procfs_core::consoles::Console;
use procfs_core::Consoles;

impl Current for Consoles {
    const PATH: &'static str = "/proc/consoles";
}

/// Returns a list of all the console devices with their respective flags and operations
pub fn consoles() -> ProcResult<Vec<Console>> {
    Consoles::current().map(|k| k.0)
}

#[cfg(test)]
mod tests {
    use procfs_core::FromBufRead;

    use procfs_core::consoles::*;

    #[test]
    fn test_consoles_correct_parsing() {
        let sample_contents = [
            "tty0                 -WU (EC  p  )       4:7",
            "ttyS0                -W- (Ep)        4:64",
            "",
        ]
        .join("\n");
        let correct = vec![
            Console {
                name: "tty0".to_owned(),
                operations: ConsoleOperations::WRITE | ConsoleOperations::UNBLANK,
                flags: ConsoleFlags::ENABLED | ConsoleFlags::PREFERRED | ConsoleFlags::PRINTK,
                device: ConsoleDeviceNumber { major: 4, minor: 7 },
            },
            Console {
                name: "ttyS0".to_owned(),
                operations: ConsoleOperations::WRITE,
                flags: ConsoleFlags::ENABLED | ConsoleFlags::PRINTK,
                device: ConsoleDeviceNumber { major: 4, minor: 64 },
            },
        ];
        let parsed = Consoles::from_buf_read(sample_contents.as_bytes()).unwrap().0;
        assert_eq!(parsed, correct);
    }
}
