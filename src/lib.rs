#![feature(nll, const_fn)]

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

use std::cmp;

lazy_static! {
    pub static ref BOOTTIME: DateTime<Local> = {
        let now = Local::now();

        let mut f =
            File::open("/proc/uptime").unwrap_or_else(|_| panic!("Unable to open /proc/uptime"));
        let mut buf = String::new();
        f.read_to_string(&mut buf)
            .unwrap_or_else(|_| panic!("Unable to read from /proc/uptime"));

        let uptime_seconds = f32::from_str(buf.split_whitespace().next().unwrap()).unwrap();
        now - chrono::Duration::milliseconds((uptime_seconds * 1000.0) as i64)
    };
    /// The  number  of  clock  ticks  per  second.
    ///
    /// This is calculated from `sysconf(_SC_CLK_TCK)`.
    pub static ref TICKS_PER_SECOND: i64 = {
        if cfg!(unix) {
            unsafe { sysconf(_SC_CLK_TCK) }
        } else {
            panic!("Not supported on non-unix platforms")
        }
    };
    pub static ref KERNEL: KernelVersion = {
        KernelVersion::current().unwrap()
    };
    pub static ref PAGESIZE: i64 = {
        if cfg!(unix) {
            unsafe { sysconf(_SC_PAGESIZE) }
        } else {
            panic!("Not supported on non-unix platforms")
        }
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

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct KernelVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

impl KernelVersion {
    pub const fn new(major: u8, minor: u8, patch: u8) -> KernelVersion {
        KernelVersion {
            major,
            minor,
            patch,
        }
    }
    pub fn current() -> ProcResult<KernelVersion> {
        let mut f = proctry!(File::open("/proc/sys/kernel/osrelease"));
        let mut buf = String::new();
        proctry!(f.read_to_string(&mut buf));

        ProcResult::Ok(KernelVersion::from_str(&buf).unwrap())
    }
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

        let mut s = curmax.split("/");
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
