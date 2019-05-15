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
//! use procfs::{Process, FDTarget};
//! use std::collections::HashMap;
//!
//! fn main() {
//!     let all_procs = procfs::all_processes();
//!
//!     // build up a map between socket inodes and processes:
//!     let mut map: HashMap<u32, &Process> = HashMap::new();
//!     for process in &all_procs {
//!         if let Ok(fds) = process.fd() {
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
extern crate libflate;

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

use crate::platform_specific_items::*;

use std::collections::HashMap;
use std::ffi::CStr;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem;
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use chrono::{DateTime, Local};

const PROC_CONFIG_GZ: &str = "/proc/config.gz";
const BOOT_CONFIG: &str = "/boot/config";

trait IntoOption<T> {
    fn into_option(t: Self) -> Option<T>;
}

impl<T> IntoOption<T> for Option<T> {
    fn into_option(t: Option<T>) -> Option<T> {
        t
    }
}

impl<T, R> IntoOption<T> for Result<T, R> {
    fn into_option(t: Result<T, R>) -> Option<T> {
        t.ok()
    }
}

#[macro_use]
macro_rules! expect {
    ($e:expr) => {
        crate::IntoOption::into_option($e).unwrap_or_else(|| {
            panic!(
                "Failed to unwrap {}. Please report this as a procfs bug.",
                stringify!($e)
            )
        })
    };
    ($e:expr, $msg:expr) => {
        crate::IntoOption::into_option($e).unwrap_or_else(|| {
            panic!(
                "Failed to unwrap {} ({}). Please report this as a procfs bug.",
                stringify!($e),
                $msg
            )
        })
    };
}

#[macro_use]
macro_rules! from_str {
    ($t:tt, $e:expr) => {{
        let e = $e;
        $t::from_str_radix(e, 10).unwrap_or_else(|_| {
            panic!(
                "Failed to parse {} ({:?}) as a {}. Please report this as a procfs bug.",
                stringify!($e),
                e,
                stringify!($t),
            )
        })
    }};
    ($t:tt, $e:expr, $radix:expr) => {{
        let e = $e;
        $t::from_str_radix(e, $radix).unwrap_or_else(|_| {
            panic!(
                "Failed to parse {} ({:?}) as a {}. Please report this as a procfs bug.",
                stringify!($e),
                e,
                stringify!($t)
            )
        })
    }};
    ($t:tt, $e:expr, $radix:expr, pid:$pid:expr) => {{
        let e = $e;
        $t::from_str_radix(e, $radix).unwrap_or_else(|_| {
            panic!(
                "Failed to parse {} ({:?}) as a {} (pid {}). Please report this as a procfs bug.",
                stringify!($e),
                e,
                stringify!($t),
                $pid
            )
        })
    }};
}

pub(crate) fn read_file<P: AsRef<Path>>(path: P) -> ProcResult<String> {
    let mut f = FileWrapper::open(path)?;
    let mut buf = String::new();
    f.read_to_string(&mut buf)?;
    Ok(buf)
}

pub(crate) fn write_file<P: AsRef<Path>, T: AsRef<[u8]>>(path: P, buf: T) -> ProcResult<()> {
    let mut f = File::open(path)?;
    f.write_all(buf.as_ref())?;
    Ok(())
}

pub(crate) fn read_value<P: AsRef<Path>, T: FromStr<Err = E>, E: fmt::Debug>(
    path: P,
) -> ProcResult<T> {
    read_file(path).map(|buf| buf.trim().parse().unwrap())
}

pub(crate) fn write_value<P: AsRef<Path>, T: fmt::Display>(path: P, value: T) -> ProcResult<()> {
    write_file(path, value.to_string().as_bytes())
}

mod process;
pub use crate::process::*;

mod meminfo;
pub use crate::meminfo::*;

mod net;
pub use crate::net::*;

mod cpuinfo;
pub use crate::cpuinfo::*;

mod cgroups;
pub use crate::cgroups::*;

pub mod sys;
pub use crate::sys::kernel::Version as KernelVersion;

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

fn convert_to_kibibytes(num: u64, unit: &str) -> u64 {
    match unit {
        "B" => num,
        "KiB" | "kiB" | "kB" | "KB" => num * 1024,
        "MiB" | "miB" | "MB" | "mB" => num * 1024 * 1024,
        "GiB" | "giB" | "GB" | "gB" => num * 1024 * 1024 * 1024,
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

/// This is used to hold both an IO error as well as the path of the file that originated the error
#[derive(Debug)]
struct IoErrorWrapper {
    path: PathBuf,
    inner: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl std::error::Error for IoErrorWrapper {}
impl fmt::Display for IoErrorWrapper {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        if let Some(inner) = &self.inner {
            write!(f, "IO Error({}): {}", self.path.display(), inner)
        } else {
            write!(f, "IO Error({})", self.path.display())
        }
    }
}

/// A wrapper around a `File` that remembers the name of the path
struct FileWrapper {
    inner: File,
    path: PathBuf,
}

impl FileWrapper {
    fn open<P: AsRef<Path>>(path: P) -> Result<FileWrapper, io::Error> {
        let p = path.as_ref();
        match File::open(&p) {
            Ok(f) => Ok(FileWrapper {
                inner: f,
                path: p.to_owned(),
            }),
            Err(e) => {
                let kind = e.kind();
                Err(io::Error::new(
                    kind,
                    IoErrorWrapper {
                        path: p.to_owned(),
                        inner: e.into_inner(),
                    },
                ))
            }
        }
    }
}

macro_rules! wrap_io_error {
    ($path:expr, $expr:expr) => {
        match $expr {
            Ok(v) => Ok(v),
            Err(e) => {
                let kind = e.kind();
                Err(io::Error::new(
                    kind,
                    IoErrorWrapper {
                        path: $path.clone(),
                        inner: e.into_inner(),
                    },
                ))
            }
        }
    };
}

impl Read for FileWrapper {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        wrap_io_error!(self.path, self.inner.read(buf))
    }
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        wrap_io_error!(self.path, self.inner.read_to_end(buf))
    }
    fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
        wrap_io_error!(self.path, self.inner.read_to_string(buf))
    }
    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        wrap_io_error!(self.path, self.inner.read_exact(buf))
    }
}

pub type ProcResult<T> = Result<T, ProcError>;

/// Error type for most procfs functions.
///
/// Most of the variants have an `Option<PathBuf>` component.  If the error root cause was related
/// to some operation on a file, the path of this file will be stored in this component.
#[derive(Debug)]
pub enum ProcError {
    /// A standard permission denied error.
    ///
    /// This will be a common error, since some files in the procfs filesystem are only readable by
    /// the root user.
    PermissionDenied(Option<PathBuf>),
    /// This might mean that the process no longer exists, or that your kernel doesn't support the
    /// feature you are trying to use.
    NotFound(Option<PathBuf>),
    /// This might mean that a procfs file has incomplete contents.
    Incomplete(Option<PathBuf>),
    /// Any other IO error (rare).
    Io(std::io::Error, Option<PathBuf>),
    /// Any other non-IO error (very rare).
    Other(String),
}

impl From<std::io::Error> for ProcError {
    fn from(io: std::io::Error) -> Self {
        use std::io::ErrorKind;
        let kind = io.kind();
        let path: Option<PathBuf> = io.get_ref().and_then(|inner| {
            if let Some(ref inner) = inner.downcast_ref::<IoErrorWrapper>() {
                Some(inner.path.clone())
            } else {
                None
            }
        });
        match kind {
            ErrorKind::PermissionDenied => ProcError::PermissionDenied(path),
            ErrorKind::NotFound => ProcError::NotFound(path),
            _other => ProcError::Io(io, path),
        }
    }
}

impl std::fmt::Display for ProcError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self {
            // Variants with paths:
            ProcError::PermissionDenied(Some(p)) => write!(f, "Permission Denied: {}", p.display()),
            ProcError::NotFound(Some(p)) => write!(f, "File not found: {}", p.display()),
            ProcError::Incomplete(Some(p)) => write!(f, "Data incomplete: {}", p.display()),
            ProcError::Io(inner, Some(p)) => {
                write!(f, "Unexpected IO error({}): {}", p.display(), inner)
            }
            // Variants without paths:
            ProcError::PermissionDenied(None) => write!(f, "Permission Denied"),
            ProcError::NotFound(None) => write!(f, "File not found"),
            ProcError::Incomplete(None) => write!(f, "Data incomplete"),
            ProcError::Io(inner, None) => write!(f, "Unexpected IO error: {}", inner),

            ProcError::Other(s) => write!(f, "Uknown error {}", s),
        }
    }
}

impl std::error::Error for ProcError {}

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
        let mut f = FileWrapper::open("/proc/loadavg")?;
        let mut s = String::new();
        f.read_to_string(&mut s)?;
        let mut s = s.split_whitespace();

        let one = f32::from_str(s.next().unwrap()).unwrap();
        let five = f32::from_str(s.next().unwrap()).unwrap();
        let fifteen = f32::from_str(s.next().unwrap()).unwrap();
        let curmax = s.next().unwrap();
        let latest_pid = u32::from_str(s.next().unwrap()).unwrap();

        let mut s = curmax.split('/');
        let cur = u32::from_str(s.next().unwrap()).unwrap();
        let max = u32::from_str(s.next().unwrap()).unwrap();

        Ok(LoadAverage {
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

    let mut f = FileWrapper::open("/proc/uptime")?;
    let mut buf = String::new();
    f.read_to_string(&mut buf)?;

    let uptime_seconds = f32::from_str(buf.split_whitespace().next().unwrap()).unwrap();
    Ok(now - chrono::Duration::milliseconds((uptime_seconds * 1000.0) as i64))
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

#[derive(Debug, PartialEq)]
pub enum ConfigSetting {
    Yes,
    Module,
    Value(String),
}
/// Returns a configuration options used to build the currently running kernel
///
/// If CONFIG_KCONFIG_PROC is available, the config is read from `/proc/config.gz`.
/// Else look in `/boot/config-$(uname -r)` or `/boot/config` (in that order).
pub fn kernel_config() -> ProcResult<HashMap<String, ConfigSetting>> {
    use libflate::gzip::Decoder;
    use std::io::{BufRead, BufReader};

    let reader: Box<BufRead> = if Path::new(PROC_CONFIG_GZ).exists() {
        let file = FileWrapper::open(PROC_CONFIG_GZ)?;
        let decoder = Decoder::new(file)?;
        Box::new(BufReader::new(decoder))
    } else {
        let mut kernel: libc::utsname = unsafe { mem::zeroed() };

        if unsafe { libc::uname(&mut kernel) != 0 } {
            return Err(ProcError::Other("Failed to call uname()".to_string()));
        }

        let filename = format!(
            "{}-{}",
            BOOT_CONFIG,
            unsafe { CStr::from_ptr(kernel.release.as_ptr() as *const c_char) }.to_string_lossy()
        );

        if Path::new(&filename).exists() {
            let file = FileWrapper::open(filename)?;
            Box::new(BufReader::new(file))
        } else {
            let file = FileWrapper::open(BOOT_CONFIG)?;
            Box::new(BufReader::new(file))
        }
    };

    let mut map = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        if line.starts_with('#') {
            continue;
        }
        if line.contains('=') {
            let mut s = line.splitn(2, '=');
            let name = expect!(s.next()).to_owned();
            let value = match expect!(s.next()) {
                "y" => ConfigSetting::Yes,
                "m" => ConfigSetting::Module,
                s => ConfigSetting::Value(s.to_owned()),
            };
            map.insert(name, value);
        }
    }

    Ok(map)
}

pub fn meminfo() -> ProcResult<Meminfo> {
    Meminfo::new()
}

#[cfg(test)]
mod tests {
    extern crate failure;
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

    #[test]
    fn test_from_str() {
        assert_eq!(from_str!(u8, "12"), 12);
        assert_eq!(from_str!(u8, "A", 16), 10);
    }

    #[test]
    #[should_panic]
    fn test_from_str_panic() {
        let s = "four";
        from_str!(u8, s);
    }

    #[test]
    fn test_kernel_config() {
        // TRAVIS
        // we don't have access to the kernel_config on travis, so skip that test there
        match std::env::var("TRAVIS") {
            Ok(ref s) if s == "true" => return,
            _ => {}
        }

        let config = kernel_config().unwrap();
        println!("{:#?}", config);
    }

    #[test]
    fn test_file_io_errors() {
        fn inner<P: AsRef<Path>>(p: P) -> Result<(), ProcError> {
            let mut file = FileWrapper::open(p)?;

            let mut buf = [0; 128];
            file.read_exact(&mut buf[0..128])?;

            Ok(())
        }

        let err = inner("/this_should_not_exist").unwrap_err();
        println!("{}", err);

        match err {
            ProcError::NotFound(Some(p)) => {
                assert_eq!(p, Path::new("/this_should_not_exist"));
            }
            x => panic!("Unexpected return value: {:?}", x),
        }

        match inner("/proc/loadavg") {
            Err(ProcError::Io(_, Some(p))) => {
                assert_eq!(p, Path::new("/proc/loadavg"));
            }
            x => panic!("Unexpected return value: {:?}", x),
        }
    }

    /// Test that our error type can be easily used with the `failure` crate
    #[test]
    fn test_failure() {
        fn inner() -> Result<(), failure::Error> {
            let _load = LoadAverage::new()?;
            Ok(())
        }
        let _ = inner();

        fn inner2() -> Result<(), failure::Error> {
            let proc = Process::new(1)?;
            let _io = proc.maps()?;
            Ok(())
        }

        let _ = inner2();
        // Unwrapping this failure should produce a message that looks like:
        // thread 'tests::test_failure' panicked at 'called `Result::unwrap()` on an `Err` value: PermissionDenied(Some("/proc/1/maps"))', src/libcore/result.rs:997:5
    }
}
