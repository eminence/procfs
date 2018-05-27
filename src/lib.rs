#![feature(nll)]

#[cfg(unix)]
extern crate libc;
#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate lazy_static;
extern crate chrono;

#[cfg(unix)]
use libc::pid_t;

#[cfg(windows)]
type pid_t = i32; // just to make things build on windows in my IDE

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
        unsafe { libc::sysconf(libc::_SC_CLK_TCK) }

    };
}


pub struct KernelVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: Option<u8>,
}

impl KernelVersion {
    pub fn new(major: u8, minor: u8, patch: u8) -> KernelVersion {
        KernelVersion {
            major,
            minor,
            patch: Some(patch)
        }
        
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
}
