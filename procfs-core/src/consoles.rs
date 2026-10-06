//! Structs related to consoles information.
//! Refer to the [kernel docs](https://docs.kernel.org/filesystems/proc.html#proc-consoles)
//! for more info about the file parsing and
//! [struct console](https://docs.kernel.org/driver-api/tty/console.html) for the description
//! of what each option means.

use std::io::BufRead;

use bitflags::bitflags;
#[cfg(feature = "serde1")]
use serde::{Deserialize, Serialize};

use crate::ProcResult;

bitflags! {
    /// Shows some basic information of the device taken from `struct console`.
    #[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
    #[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
    pub struct ConsoleOperations: u32 {
        /// The console has a `read` callback for console input
        /// Does not represent UNIX `read` permissions.
        const READ    = 1;
        /// The console has a legacy write callback to output messages
        /// or the console has the CON_NBCON capability.
        /// Does not represent UNIX `write` permissions.
        const WRITE   = 1 << 1;
        /// The console has an unblank callback
        const UNBLANK = 1 << 2;
    }
}

impl ConsoleOperations {
    fn from_str(s: &str) -> ProcResult<Self> {
        let mut console_operations = ConsoleOperations::empty();
        for ch in s.chars() {
            match ch {
                'R' => console_operations.insert(ConsoleOperations::READ),
                'W' => console_operations.insert(ConsoleOperations::WRITE),
                'U' => console_operations.insert(ConsoleOperations::UNBLANK),
                c if c.is_whitespace() || c == '-' => continue,
                c => return Err(build_internal_error!(format!("Unknown console operation: {c}"))),
            }
        }
        Ok(console_operations)
    }
}

bitflags! {
    /// Flags for device properties. Provides some information about `enum cons_flags`
    /// flags enabled for the console device.
    #[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
    #[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
    pub struct ConsoleFlags: u32 {
        /// Indicates if a console is allowed to print records.
        /// If false, the console also will not advance to later records.
        /// - `/proc/console` flag: `E`
        /// - `cons_flags` constant: `CON_ENABLED`
        const ENABLED   = 1;
        /// It is preferred console. This means the console driver is backing `/dev/console`
        /// - `/proc/console` flag: `C`
        /// - `cons_flags` constant: `CON_CONSDEV`
        const PREFERRED = 1 << 1;
        /// Marks the console driver as early console driver which is used during boot
        /// before the real driver becomes available.
        /// It will be automatically unregistered when the real console driver
        /// is registered unless “keep_bootcon” parameter is used.
        /// - `/proc/console` flag: `B`
        /// - `cons_flags` constant: `CON_BOOT`
        const BOOT      = 1 << 2;
        /// Used by newly registered consoles to avoid duplicate output of messages that
        /// were already shown by boot consoles or read by userspace via `syslog()` syscall.
        /// - `/proc/console` flag: `p`
        /// - `cons_flags` constant: `CON_PRINTBUFFER`
        const PRINTK    = 1 << 3;
        /// Indicates a braille device which is exempt from receiving
        /// the printk spam for obvious reasons.
        /// - `/proc/console` flag: `b`
        /// - `cons_flags` constant: `CON_BRL`
        const BRAILE    = 1 << 4;
        /// A misnomed historical flag which tells the core code that the legacy
        /// `console::write` callback can be invoked on a CPU which is marked OFFLINE.
        /// That is misleading as it suggests that there is no contextual limit for
        /// invoking the callback. The original motivation was readiness of the per-CPU areas.
        /// - `/proc/console` flag: `a`
        /// - `cons_flags` constant: `CON_ANYTIME`
        const SAFE      = 1 << 5;
        /// That's a strange one:
        /// [current `/proc/console` docs](https://docs.kernel.org/filesystems/proc.html#proc-consoles)
        /// don't list the option. However, the source code for procfs actually
        /// [has this option](https://github.com/torvalds/linux/blob/4056b3c9d3c92ea45955641dbafeb9b960e146ef/fs/proc/consoles.c#L15). Therefore we include it
        /// here.
        ///
        /// Console can operate outside of the legacy style console_lock constraints.
        /// - `/proc/console` flag: `N`
        /// - `cons_flags` constant: `CON_NBCON`
        const NBCON      = 1 << 6;
    }
}

impl ConsoleFlags {
    fn from_str(s: &str) -> ProcResult<Self> {
        let mut console_operations = ConsoleFlags::empty();
        for ch in s.chars() {
            match ch {
                'E' => console_operations.insert(ConsoleFlags::ENABLED),
                'C' => console_operations.insert(ConsoleFlags::PREFERRED),
                'B' => console_operations.insert(ConsoleFlags::BOOT),
                'p' => console_operations.insert(ConsoleFlags::PRINTK),
                'b' => console_operations.insert(ConsoleFlags::BRAILE),
                'a' => console_operations.insert(ConsoleFlags::SAFE),
                'N' => console_operations.insert(ConsoleFlags::NBCON),
                c if c.is_whitespace() => continue,
                c => return Err(build_internal_error!(format!("Unknown flag: {c}"))),
            }
        }
        Ok(console_operations)
    }
}

/// Major and minor numbers of the console character device
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct ConsoleDeviceNumber {
    pub major: u32,
    pub minor: u32,
}

impl ConsoleDeviceNumber {
    fn from_str(s: &str) -> ProcResult<Self> {
        let mut split = s.trim().split(":");
        let major = from_str!(u32, expect!(split.next()));
        let minor = from_str!(u32, expect!(split.next()));
        Ok(ConsoleDeviceNumber { major, minor })
    }
}

/// Console character device representation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
pub struct Console {
    /// Console character device name (like `tty0` or `ttyS0`)
    pub name: String,
    pub operations: ConsoleOperations,
    pub flags: ConsoleFlags,
    pub device: ConsoleDeviceNumber,
}

impl Console {
    /// This parses one line of `/proc/consoles` with a result
    /// of a single console device
    fn from_line(line: &str) -> ProcResult<Self> {
        // split str into 3 parts
        let mut split = line.split(|c| c == '(' || c == ')');

        let name_and_operations = expect!(split.next());
        let (name, operations) = {
            let mut split = name_and_operations.split_whitespace();
            let name = expect!(split.next());
            let operations_str = expect!(split.next());
            (name.to_owned(), expect!(ConsoleOperations::from_str(operations_str)))
        };

        let flags = expect!(ConsoleFlags::from_str(expect!(split.next())));
        let device = expect!(ConsoleDeviceNumber::from_str(expect!(split.next())));
        Ok(Console {
            name,
            operations,
            flags,
            device,
        })
    }
}

/// A list of console character devices.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
pub struct Consoles(pub Vec<Console>);

impl crate::FromBufRead for Consoles {
    fn from_buf_read<R: BufRead>(r: R) -> ProcResult<Self> {
        let mut v = Vec::new();

        for line in r.lines() {
            let line = line?;
            if !line.is_empty() {
                v.push(Console::from_line(&line)?);
            }
        }
        Ok(Consoles(v))
    }
}
