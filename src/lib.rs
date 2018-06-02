#![feature(nll, const_fn)]

#[cfg(unix)]
extern crate libc;
#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate lazy_static;
extern crate chrono;

#[cfg(unix)]
mod platform_specific_items {
    pub use libc::pid_t;
    pub use libc::sysconf;
    pub use libc::_SC_CLK_TCK;
}


// Even though this lib isn't supported on windows, I want it to at least typecheck
#[cfg(windows)]
mod platform_specific_items {
    pub type pid_t = i32; // just to make things build on windows in my IDE
    pub fn sysconf(_: i32) -> i64 { panic!() }
    pub const _SC_CLK_TCK: i32 = 2;
}

use platform_specific_items::*;

use std::fs::File;
use std::io::{self, ErrorKind, Read};
use std::str::FromStr;

use chrono::{DateTime, Local};


#[macro_use]
macro_rules! proctry {
    ($e:expr) => {
        match $e {
            Ok(x) => x,
            Err(ref e) if e.kind() == ErrorKind::PermissionDenied => {
                return ProcResult::PermissionDenied
            }
            Err(_) => return ProcResult::NotFound,
        }
    };
}


mod process;
pub use process::*;
use std::cmp;


lazy_static! {
    pub static ref BOOTTIME: DateTime<Local> = {
        let now = Local::now();

        let mut f = File::open("/proc/uptime").unwrap_or_else(|_| panic!("Unable to open /proc/uptime"));
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap_or_else(|_| panic!("Unable to read from /proc/uptime"));

        let uptime_seconds = f32::from_str(buf.split_whitespace().next().unwrap()).unwrap();
        now - chrono::Duration::milliseconds((uptime_seconds * 1000.0) as i64)
    };

    pub static ref TICKS_PER_SECOND: i64 = {
        if cfg!(unix) {
        unsafe { sysconf(_SC_CLK_TCK) }
        } else {
            panic!("Not supported on non-unix platforms")
        }
    };

    pub static ref KERNEL: KernelVersion = {
        let mut f = File::open("/proc/sys/kernel/osrelease").unwrap_or_else(|_| panic!("Unable to open /proc/sys/kernel/osrelease"));
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap_or_else(|_| panic!("Unable to read from /proc/sys/kernel/osrelease"));

        KernelVersion::from_str(&buf).unwrap()
    };
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
            patch
        }
        
    }
    pub fn from_str(s: &str) -> Result<KernelVersion, &'static str> {
        let mut s = s.split('-');
        let mut kernel = s.next().unwrap();
        let mut kernel_split = kernel.split('.');

        let major = kernel_split.next().ok_or("Missing major version component")?;
        let minor = kernel_split.next().ok_or("Missing minor version component")?;
        let patch = kernel_split.next().ok_or("Missing patch version component")?;

        let major = major.parse().map_err(|_| "Failed to parse major version")?;
        let minor = minor.parse().map_err(|_| "Failed to parse minor version")?;
        let patch = patch.parse().map_err(|_| "Failed to parse patch version")?;

        Ok(KernelVersion{
            major, minor, patch

        })
    }
}


impl cmp::Ord for KernelVersion {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
       match self.major.cmp(&other.major) {
           cmp::Ordering::Equal => match self.minor.cmp(&other.minor) {
               cmp::Ordering::Equal => { self.patch.cmp(&other.patch)},
               x => x
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



macro_rules! kernel {
    ($a:tt . $b:tt . $c:tt) => {
       KernelVersion::new($a, $b, $c) 
    };
}



/// Common result type of procfs operations.
#[derive(Debug)]
pub enum ProcResult<T> {
    Ok(T),
    PermissionDenied,
    NotFound,
}

impl<T> ProcResult<T> {
    pub fn unwrap(self) -> T {
        match self {
            ProcResult::Ok(v) => v,
            _ => panic!("ProcResult doesn't contain any data")
        }
    }

}

trait ProcFrom<T> {
    fn from(s: T) -> Self;
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_macro() {
        let a = kernel!(3 . 32 . 4);
    }

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
}
