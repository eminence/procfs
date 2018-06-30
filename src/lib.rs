//! This crate provides to an interface into the linux `procfs` filesystem, usually mounted at
//! `/proc`.
//!
//! This is a pseudo-filesystem which is available on most every linux system and provides an
//! interface to kernel data structures.
//!
//!
//! # Kernel support
//!
//! Not all fields/data are available in each kernel.  Some fields were added in specific kernel
//! releases, and other fields are only present in certain kernel configuration options are
//! enabled.  These are represented as `Option` fields in this crate.
//!
//! This crate aims to support all 2.6 kernels
//!
//! # Documentation
//!
//! In almost all cases, the documentation is taken from the
//! [`proc.5`](http://man7.org/linux/man-pages/man5/proc.5.html) manual page.  This means that
//! sometimes the style of writing is not very "rusty", or may do things like reference related files
//! (instead of referencing related structs).  Contributions to improve this are welcome.
//!
//! # Panicing
//!
//! This crate is not panic-free.  It will panic if it encounters data in some unexpected format;
//! this represents a bug in this crate, and should be [reported](https://github.com/eminence/procfs).
//!
//! # Examples
//!
//! Here's a small example that prints out all processes that are running on the same tty as the calling
//! process.  This is very similar to what "ps" does in its default mode.  You can run this example
//! yourself with:
//!
//! > cargo run --example=ps
//!
//! ```rust
//! extern crate procfs;
//!
//! fn main() {
//!     let me = procfs::Process::myself().unwrap();
//!     let tps = procfs::ticks_per_second().unwrap();
//!
//!     println!("{: >5} {: <8} {: >8} {}", "PID", "TTY", "TIME", "CMD");
//!
//!     let tty = format!("pty/{}", me.stat.tty_nr().1);
//!     for prc in procfs::all_processes() {
//!         if prc.stat.tty_nr == me.stat.tty_nr {
//!             // total_time is in seconds
//!             let total_time =
//!                 (prc.stat.utime + prc.stat.stime) as f32 / (tps as f32);
//!             println!(
//!                 "{: >5} {: <8} {: >8} {}",
//!                 prc.stat.pid, tty, total_time, prc.stat.comm
//!             );
//!         }
//!     }
//! }
//! ```
//!
//! Here's another example that will print out all of the open and listening TCP sockets, and their
//! corresponding processes, if know.  This mimics the "netstat" utility, but for TCP only.  You
//! can run this example yourself with:
//!
//! > cargo run --example=netstat
//!
//! ```rust
//! extern crate procfs;
//!
//! use procfs::{ProcResult, Process, FDTarget};
//! use std::collections::HashMap;
//!
//! fn main() {
//!     let all_procs = procfs::all_processes();
//!
//!     // build up a map between socket inodes and processes:
//!     let mut map: HashMap<u32, &Process> = HashMap::new();
//!     for process in &all_procs {
//!         if let ProcResult::Ok(fds) = process.fd() {
//!             for fd in fds {
//!                 if let FDTarget::Socket(inode) = fd.target {
//!                     map.insert(inode, process);
//!                 }
//!             }
//!         }
//!     }
//!
//!     // get the tcp table
//!     let tcp = procfs::tcp().unwrap();
//!     let tcp6 = procfs::tcp6().unwrap();
//!     println!("{:<26} {:<26} {:<15} {:<8} {}", "Local address", "Remote address", "State", "Inode", "PID/Program name");
//!     for entry in tcp.into_iter().chain(tcp6) {
//!         // find the process (if any) that has an open FD to this entry's inode
//!         let local_address = format!("{}", entry.local_address);
//!         let remote_addr = format!("{}", entry.remote_address);
//!         let state = format!("{:?}", entry.state);
//!         if let Some(process) = map.get(&entry.inode) {
//!             println!("{:<26} {:<26} {:<15} {:<8} {}/{}", local_address, remote_addr, state, entry.inode, process.stat.pid, process.stat.comm);
//!         } else {
//!             // We might not always be able to find the process assocated with this socket
//!             println!("{:<26} {:<26} {:<15} {:<8} -", local_address, remote_addr, state, entry.inode);
//!         }
//!     }
//! }

#[cfg(unix)]
extern crate libc;
#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate lazy_static;
extern crate byteorder;
extern crate chrono;
extern crate hex;

#[cfg(unix)]
mod platform_specific_items {
    pub use libc::pid_t;
    pub use libc::sysconf;
    pub use libc::{_SC_CLK_TCK, _SC_PAGESIZE};
}

// Even though this lib isn't supported on windows, I want it to at least typecheck
#[cfg(windows)]
mod platform_specific_items {
    pub type pid_t = i32; // just to make things build on windows in my IDE
    pub fn sysconf(_: i32) -> i64 {
        panic!()
    }
    pub const _SC_CLK_TCK: i32 = 2;
    pub const _SC_PAGESIZE: i32 = 30;
}

use platform_specific_items::*;

use std::fs::File;
use std::io::Read;
use std::str::FromStr;

use chrono::{DateTime, Local};

#[macro_use]
macro_rules! proctry {
    ($e:expr) => {
        match $e {
            Ok(x) => x,
            Err(ref e) if e.kind() == ::std::io::ErrorKind::PermissionDenied => {
                return ProcResult::PermissionDenied
            }
            Err(_) => return ProcResult::NotFound,
        }
    };
}

mod process;
pub use process::*;

mod meminfo;
pub use meminfo::*;

mod net;
pub use net::*;

mod cpuinfo;
pub use cpuinfo::*;

mod cgroups;
pub use cgroups::*;

use std::cmp;

lazy_static! {
    /// The boottime of the system.
    ///
    /// This is calculated from `/proc/uptime`.
    static ref BOOTTIME: DateTime<Local> = {
        boot_time().unwrap()
    };
    /// The number of clock ticks per second.
    ///
    /// This is calculated from `sysconf(_SC_CLK_TCK)`.
    static ref TICKS_PER_SECOND: i64 = {
        ticks_per_second().unwrap()
    };
    /// The version of the currently running kernel.
    ///
    /// This is a lazily constructed static.  You can also get this information via
    /// [KernelVersion::new()].
    static ref KERNEL: KernelVersion = {
        KernelVersion::current().unwrap()
    };
    /// Memory page size, in bytes.
    ///
    /// This is calculated from `sysconf(_SC_PAGESIZE)`.
    static ref PAGESIZE: i64 = {
        page_size().unwrap()
    };
}

fn convert_to_bytes(num: u64, unit: &str) -> u64 {
    match unit {
        "B" => num,
        "KiB" | "kiB" => num * 1024,
        "kB" | "KB" => num * 1000,
        "MiB" | "miB" => num * 1024 * 1024,
        "MB" | "mB" => num * 1000 * 1000,
        "GiB" | "giB" => num * 1024 * 1024 * 1024,
        "GB" | "gB" => num * 1000 * 1000 * 1000,
        unknown => panic!("Unknown unit type {}", unknown),
    }
}

trait FromStrRadix: Sized {
    fn from_str_radix(t: &str, radix: u32) -> Result<Self, std::num::ParseIntError>;
}

impl FromStrRadix for u64 {
    fn from_str_radix(s: &str, radix: u32) -> Result<u64, std::num::ParseIntError> {
        u64::from_str_radix(s, radix)
    }
}
impl FromStrRadix for i32 {
    fn from_str_radix(s: &str, radix: u32) -> Result<i32, std::num::ParseIntError> {
        i32::from_str_radix(s, radix)
    }
}

fn split_into_num<T: FromStrRadix>(s: &str, sep: char, radix: u32) -> (T, T) {
    let mut s = s.split(sep);
    let a = match FromStrRadix::from_str_radix(s.next().unwrap(), radix) {
        Ok(v) => v,
        _ => panic!(),
    };
    let b = match FromStrRadix::from_str_radix(s.next().unwrap(), radix) {
        Ok(v) => v,
        _ => panic!(),
    };
    (a, b)
}

/// Represents a kernel version, in major.minor.release version.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct KernelVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

impl KernelVersion {
    pub fn new(major: u8, minor: u8, patch: u8) -> KernelVersion {
        KernelVersion {
            major,
            minor,
            patch,
        }
    }

    /// Returns the kernel version of the curretly running kernel.
    ///
    /// This is taken from `/proc/sys/kernel/osrelease`;
    pub fn current() -> ProcResult<KernelVersion> {
        let mut f = proctry!(File::open("/proc/sys/kernel/osrelease"));
        let mut buf = String::new();
        proctry!(f.read_to_string(&mut buf));

        ProcResult::Ok(KernelVersion::from_str(&buf).unwrap())
    }
    /// Parses a kernel version string, in major.minor.release syntax.
    ///
    /// Note that any extra information (stuff after a dash) is ignored.
    ///
    /// # Example
    ///
    /// ```
    /// # use procfs::KernelVersion;
    /// let a = KernelVersion::from_str("3.16.0-6-amd64").unwrap();
    /// let b = KernelVersion::new(3, 16, 0);
    /// assert_eq!(a, b);
    ///
    /// ```
    pub fn from_str(s: &str) -> Result<KernelVersion, &'static str> {
        let mut s = s.split('-');
        let kernel = s.next().unwrap();
        let mut kernel_split = kernel.split('.');

        let major = kernel_split
            .next()
            .ok_or("Missing major version component")?;
        let minor = kernel_split
            .next()
            .ok_or("Missing minor version component")?;
        let patch = kernel_split
            .next()
            .ok_or("Missing patch version component")?;

        let major = major.parse().map_err(|_| "Failed to parse major version")?;
        let minor = minor.parse().map_err(|_| "Failed to parse minor version")?;
        let patch = patch.parse().map_err(|_| "Failed to parse patch version")?;

        Ok(KernelVersion {
            major,
            minor,
            patch,
        })
    }
}

impl cmp::Ord for KernelVersion {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match self.major.cmp(&other.major) {
            cmp::Ordering::Equal => match self.minor.cmp(&other.minor) {
                cmp::Ordering::Equal => self.patch.cmp(&other.patch),
                x => x,
            },
            x => x,
        }
    }
}

impl cmp::PartialOrd for KernelVersion {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(&other))
    }
}

/// Common result type of procfs operations.
#[derive(Debug)]
pub enum ProcResult<T> {
    Ok(T),
    PermissionDenied,
    NotFound,
}

impl<T> ProcResult<T> {
    pub fn is_ok(&self) -> bool {
        match self {
            ProcResult::Ok(_) => true,
            _ => false,
        }
    }
}

impl<T> ProcResult<T>
where
    T: std::fmt::Debug,
{
    pub fn unwrap(self) -> T {
        match self {
            ProcResult::Ok(v) => v,
            _ => panic!("ProcResult is: {:?}", self),
        }
    }
}

trait ProcFrom<T> {
    fn from(s: T) -> Self;
}

/// Load average figures.
///
/// Load averages are calculated as the number of jobs in the run queue (state R) or waiting for
/// disk I/O (state D) averaged over 1, 5, and 15 minutes.
#[derive(Debug)]
pub struct LoadAverage {
    /// The one-minute load average
    pub one: f32,
    /// The five-minute load average
    pub five: f32,
    /// THe fifteen-minute load average
    pub fifteen: f32,
    /// The number of currently runnable kernel scheduling  entities  (processes,  threads).
    pub cur: u32,
    /// The number of kernel scheduling entities that currently exist on the system.
    pub max: u32,
    /// The fifth field is the PID of the process that was most recently created on the system.
    pub latest_pid: u32,
}

impl LoadAverage {
    /// Reads load average info from `/proc/loadavg`
    pub fn new() -> ProcResult<LoadAverage> {
        use std::fs::File;

        let mut f = proctry!(File::open("/proc/loadavg"));
        let mut s = String::new();
        proctry!(f.read_to_string(&mut s));
        let mut s = s.split_whitespace();

        let one = f32::from_str(s.next().unwrap()).unwrap();
        let five = f32::from_str(s.next().unwrap()).unwrap();
        let fifteen = f32::from_str(s.next().unwrap()).unwrap();
        let curmax = s.next().unwrap();
        let latest_pid = u32::from_str(s.next().unwrap()).unwrap();

        let mut s = curmax.split('/');
        let cur = u32::from_str(s.next().unwrap()).unwrap();
        let max = u32::from_str(s.next().unwrap()).unwrap();

        ProcResult::Ok(LoadAverage {
            one,
            five,
            fifteen,
            cur,
            max,
            latest_pid,
        })
    }
}

/// Return the number of ticks per second.
///
/// This isn't part of the proc file system, but it's a useful thing to have, since several fields
/// count in ticks.  This is calculated from `sysconf(_SC_CLK_TCK)`.
pub fn ticks_per_second() -> std::io::Result<i64> {
    if cfg!(unix) {
        match unsafe { sysconf(_SC_CLK_TCK) } {
            -1 => Err(std::io::Error::last_os_error()),
            x => Ok(x),
        }
    } else {
        panic!("Not supported on non-unix platforms")
    }
}

/// The boottime of the system.
///
/// This is calculated from `/proc/uptime`.
pub fn boot_time() -> ProcResult<DateTime<Local>> {
    let now = Local::now();

    let mut f = proctry!(File::open("/proc/uptime"));
    let mut buf = String::new();
    proctry!(f.read_to_string(&mut buf));

    let uptime_seconds = f32::from_str(buf.split_whitespace().next().unwrap()).unwrap();
    ProcResult::Ok(now - chrono::Duration::milliseconds((uptime_seconds * 1000.0) as i64))
}

/// Memory page size, in bytes.
///
/// This is calculated from `sysconf(_SC_PAGESIZE)`.
pub fn page_size() -> std::io::Result<i64> {
    if cfg!(unix) {
        match unsafe { sysconf(_SC_PAGESIZE) } {
            -1 => Err(std::io::Error::last_os_error()),
            x => Ok(x),
        }
    } else {
        panic!("Not supported on non-unix platforms")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_const() {
        println!("{:?}", *KERNEL);
    }

    #[test]
    fn test_kernel_from_str() {
        let k = KernelVersion::from_str("1.2.3").unwrap();
        assert_eq!(k.major, 1);
        assert_eq!(k.minor, 2);
        assert_eq!(k.patch, 3);

        let k = KernelVersion::from_str("4.9.16-gentoo").unwrap();
        assert_eq!(k.major, 4);
        assert_eq!(k.minor, 9);
        assert_eq!(k.patch, 16);
    }

    #[test]
    fn test_kernel_cmp() {
        let a = KernelVersion::from_str("1.2.3").unwrap();
        let b = KernelVersion::from_str("1.2.3").unwrap();
        let c = KernelVersion::from_str("1.2.4").unwrap();
        let d = KernelVersion::from_str("1.5.4").unwrap();
        let e = KernelVersion::from_str("2.5.4").unwrap();

        assert_eq!(a, b);
        assert!(a < c);
        assert!(a < d);
        assert!(a < e);
        assert!(e > d);
        assert!(e > c);
        assert!(e > b);
    }

    #[test]
    fn test_loadavg() {
        let load = LoadAverage::new().unwrap();
        println!("{:?}", load);
    }
}
