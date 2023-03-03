#![allow(unknown_lints)]
// The suggested fix with `str::parse` removes support for Rust 1.48
#![allow(clippy::from_str_radix_10)]
#![deny(broken_intra_doc_links, invalid_html_tags)]
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
//! This crate aims to support all 2.6 kernels (and newer).  WSL2 is also supported.
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
//! While previous versions of the library could panic, this current version aims to be panic-free
//! in a many situations as possible.  Whenever the procfs crate encounters a bug in its own
//! parsing code, it will return an [`InternalError`](enum.ProcError.html#variant.InternalError) error.  This should be considered a
//! bug and should be [reported](https://github.com/eminence/procfs).  If you encounter a panic,
//! please report that as well.
//!
//! # Cargo features
//!
//! The following cargo features are available:
//!
//! * `chrono` -- Default.  Optional.  This feature enables a few methods that return values as `DateTime` objects.
//! * `flate2` -- Default.  Optional.  This feature enables parsing gzip compressed `/proc/config.gz` file via the `procfs::kernel_config` method.
//! * `backtrace` -- Optional.  This feature lets you get a stack trace whenever an `InternalError` is raised.
//!
//! # Examples
//!
//! Examples can be found in the various modules shown below, or in the
//! [examples](https://github.com/eminence/procfs/tree/master/examples) folder of the code repository.
//!

pub use procfs_core::*;

use bitflags::bitflags;
use lazy_static::lazy_static;

use rustix::fd::AsFd;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{collections::HashMap, time::Duration};

#[cfg(feature = "chrono")]
use chrono::{DateTime, Local};
#[cfg(feature = "serde1")]
use serde::{Deserialize, Serialize};

const PROC_CONFIG_GZ: &str = "/proc/config.gz";
const BOOT_CONFIG: &str = "/boot/config";

macro_rules! build_internal_error {
    ($err: expr) => {
        crate::ProcError::InternalError(crate::InternalError {
            msg: format!("Internal Unwrap Error: {}", $err),
            file: file!(),
            line: line!(),
            #[cfg(feature = "backtrace")]
            backtrace: backtrace::Backtrace::new(),
        })
    };
    ($err: expr, $msg: expr) => {
        crate::ProcError::InternalError(crate::InternalError {
            msg: format!("Internal Unwrap Error: {}: {}", $msg, $err),
            file: file!(),
            line: line!(),
            #[cfg(feature = "backtrace")]
            backtrace: backtrace::Backtrace::new(),
        })
    };
}

#[allow(unused_macros)]
macro_rules! proc_panic {
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

macro_rules! expect {
    ($e:expr) => {
        match crate::IntoResult::into($e) {
            Ok(v) => v,
            Err(e) => return Err(build_internal_error!(e)),
        }
    };
    ($e:expr, $msg:expr) => {
        match crate::IntoResult::into($e) {
            Ok(v) => v,
            Err(e) => return Err(build_internal_error!(e, $msg)),
        }
    };
}

macro_rules! from_str {
    ($t:tt, $e:expr) => {{
        let e = $e;
        expect!(
            $t::from_str_radix(e, 10),
            format!("Failed to parse {} ({:?}) as a {}", stringify!($e), e, stringify!($t),)
        )
    }};
    ($t:tt, $e:expr, $radix:expr) => {{
        let e = $e;
        expect!(
            $t::from_str_radix(e, $radix),
            format!("Failed to parse {} ({:?}) as a {}", stringify!($e), e, stringify!($t))
        )
    }};
    ($t:tt, $e:expr, $radix:expr, pid:$pid:expr) => {{
        let e = $e;
        expect!(
            $t::from_str_radix(e, $radix),
            format!(
                "Failed to parse {} ({:?}) as a {} (pid {})",
                stringify!($e),
                e,
                stringify!($t),
                $pid
            )
        )
    }};
}

macro_rules! wrap_io_error {
    ($path:expr, $expr:expr) => {
        match $expr {
            Ok(v) => Ok(v),
            Err(e) => {
                let kind = e.kind();
                Err(::std::io::Error::new(
                    kind,
                    crate::IoErrorWrapper {
                        path: $path.to_owned(),
                        inner: e.into(),
                    },
                ))
            }
        }
    };
}

pub(crate) fn read_file<P: AsRef<Path>>(path: P) -> ProcResult<String> {
    let mut f = FileWrapper::open(path)?;
    let mut buf = String::new();
    f.read_to_string(&mut buf)?;
    Ok(buf)
}

pub(crate) fn write_file<P: AsRef<Path>, T: AsRef<[u8]>>(path: P, buf: T) -> ProcResult<()> {
    let mut f = OpenOptions::new().read(false).write(true).open(path)?;
    f.write_all(buf.as_ref())?;
    Ok(())
}

pub(crate) fn read_value<P, T, E>(path: P) -> ProcResult<T>
where
    P: AsRef<Path>,
    T: FromStr<Err = E>,
    ProcError: From<E>,
{
    let val = read_file(path)?;
    Ok(<T as FromStr>::from_str(val.trim())?)
    //Ok(val.trim().parse()?)
}

pub(crate) fn write_value<P: AsRef<Path>, T: fmt::Display>(path: P, value: T) -> ProcResult<()> {
    write_file(path, value.to_string().as_bytes())
}

pub mod process;

mod meminfo;
pub use crate::meminfo::*;

mod sysvipc_shm;
pub use crate::sysvipc_shm::*;

pub mod net;

mod cpuinfo;
pub use crate::cpuinfo::*;

mod cgroups;
pub use crate::cgroups::*;

pub mod sys;
pub use crate::sys::kernel::BuildInfo as KernelBuildInfo;
pub use crate::sys::kernel::Type as KernelType;
pub use crate::sys::kernel::Version as KernelVersion;

mod pressure;
pub use crate::pressure::*;

mod diskstats;
pub use diskstats::*;

mod locks;
pub use locks::*;

pub mod keyring;

mod uptime;
pub use uptime::*;

mod iomem;
pub use iomem::*;

mod kpageflags;
pub use kpageflags::*;

mod kpagecount;
pub use kpagecount::*;

lazy_static! {
    /// The number of clock ticks per second.
    ///
    /// This is calculated from `sysconf(_SC_CLK_TCK)`.
    static ref TICKS_PER_SECOND: u64 = {
        ticks_per_second()
    };
    /// The version of the currently running kernel.
    ///
    /// This is a lazily constructed static.  You can also get this information via
    /// [KernelVersion::new()].
    static ref KERNEL: ProcResult<KernelVersion> = {
        KernelVersion::current()
    };
    /// Memory page size, in bytes.
    ///
    /// This is calculated from `sysconf(_SC_PAGESIZE)`.
    static ref PAGESIZE: u64 = {
        page_size()
    };
}

fn convert_to_kibibytes(num: u64, unit: &str) -> ProcResult<u64> {
    match unit {
        "B" => Ok(num),
        "KiB" | "kiB" | "kB" | "KB" => Ok(num * 1024),
        "MiB" | "miB" | "MB" | "mB" => Ok(num * 1024 * 1024),
        "GiB" | "giB" | "GB" | "gB" => Ok(num * 1024 * 1024 * 1024),
        unknown => Err(build_internal_error!(format!("Unknown unit type {}", unknown))),
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
        let f = wrap_io_error!(p, File::open(p))?;
        Ok(FileWrapper {
            inner: f,
            path: p.to_owned(),
        })
    }
    fn open_at<P, Q, Fd: AsFd>(root: P, dirfd: Fd, path: Q) -> Result<FileWrapper, io::Error>
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
    {
        use rustix::fs::{Mode, OFlags};

        let p = root.as_ref().join(path.as_ref());
        let fd = wrap_io_error!(
            p,
            rustix::fs::openat(dirfd, path.as_ref(), OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        )?;
        Ok(FileWrapper {
            inner: File::from(fd),
            path: p,
        })
    }

    /// Returns the inner file
    fn inner(self) -> File {
        self.inner
    }
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

impl Seek for FileWrapper {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        wrap_io_error!(self.path, self.inner.seek(pos))
    }
}

pub trait ProcfsLocal: Sized {
    fn new() -> ProcResult<Self>;
}

impl ProcfsLocal for LoadAverage {
    /// Reads load average info from `/proc/loadavg`
    fn new() -> ProcResult<Self> {
        LoadAverage::from_reader(FileWrapper::open("/proc/loadavg")?)
    }
}

/// Return the number of ticks per second.
///
/// This isn't part of the proc file system, but it's a useful thing to have, since several fields
/// count in ticks.  This is calculated from `sysconf(_SC_CLK_TCK)`.
pub fn ticks_per_second() -> u64 {
    rustix::param::clock_ticks_per_second()
}

/// The boot time of the system, as a `DateTime` object.
///
/// This is calculated from `/proc/stat`.
///
/// This function requires the "chrono" features to be enabled (which it is by default).
#[cfg(feature = "chrono")]
pub fn boot_time() -> ProcResult<DateTime<Local>> {
    use chrono::TimeZone;
    let secs = boot_time_secs()?;

    let date_time = expect!(chrono::Local.timestamp_opt(secs as i64, 0).single());

    Ok(date_time)
}

/// The boottime of the system, in seconds since the epoch
///
/// This is calculated from `/proc/stat`.
///
#[cfg_attr(
    not(feature = "chrono"),
    doc = "If you compile with the optional `chrono` feature, you can use the `boot_time()` method to get the boot time as a `DateTime` object."
)]
#[cfg_attr(
    feature = "chrono",
    doc = "See also [boot_time()] to get the boot time as a `DateTime`"
)]
pub fn boot_time_secs() -> ProcResult<u64> {
    BOOT_TIME.with(|x| {
        let mut btime = x.borrow_mut();
        if let Some(btime) = *btime {
            Ok(btime)
        } else {
            let stat = KernelStats::new()?;
            *btime = Some(stat.btime);
            Ok(stat.btime)
        }
    })
}

thread_local! {
    static BOOT_TIME : std::cell::RefCell<Option<u64>> = std::cell::RefCell::new(None);
}

/// Memory page size, in bytes.
///
/// This is calculated from `sysconf(_SC_PAGESIZE)`.
pub fn page_size() -> u64 {
    rustix::param::page_size() as u64
}

/// Returns a configuration options used to build the currently running kernel
///
/// If CONFIG_KCONFIG_PROC is available, the config is read from `/proc/config.gz`.
/// Else look in `/boot/config-$(uname -r)` or `/boot/config` (in that order).
///
/// # Notes
/// Reading the compress `/proc/config.gz` is only supported if the `flate2` feature is enabled
/// (which it is by default).
#[cfg_attr(feature = "flate2", doc = "The flate2 feature is currently enabled")]
#[cfg_attr(not(feature = "flate2"), doc = "The flate2 feature is NOT currently enabled")]
pub fn kernel_config() -> ProcResult<HashMap<String, ConfigSetting>> {
    let reader: Box<dyn Read> = if Path::new(PROC_CONFIG_GZ).exists() && cfg!(feature = "flate2") {
        #[cfg(feature = "flate2")]
        {
            let file = FileWrapper::open(PROC_CONFIG_GZ)?;
            let decoder = flate2::read::GzDecoder::new(file);
            Box::new(decoder)
        }
        #[cfg(not(feature = "flate2"))]
        {
            unreachable!("flate2 feature not enabled")
        }
    } else {
        let kernel = rustix::process::uname();

        let filename = format!("{}-{}", BOOT_CONFIG, kernel.release().to_string_lossy());

        match FileWrapper::open(filename) {
            Ok(file) => Box::new(BufReader::new(file)),
            Err(e) => match e.kind() {
                io::ErrorKind::NotFound => {
                    let file = FileWrapper::open(BOOT_CONFIG)?;
                    Box::new(file)
                }
                _ => return Err(e.into()),
            },
        }
    };

    kernel_config_from_read(reader)
}

impl ProcfsLocal for KernelStats {
    fn new() -> ProcResult<KernelStats> {
        KernelStats::from_reader(FileWrapper::open("/proc/stat")?, ticks_per_second())
    }
}

/// Get various virtual memory statistics
///
/// Since the exact set of statistics will vary from kernel to kernel,
/// and because most of them are not well documented, this function
/// returns a HashMap instead of a struct.  Consult the kernel source
/// code for more details of this data.
///
/// This data is taken from the `/proc/vmstat` file.
///
/// (since Linux 2.6.0)
pub fn vmstat() -> ProcResult<HashMap<String, i64>> {
    vmstat_from_read(FileWrapper::open("/proc/vmstat")?)
}

/// Get a list of loaded kernel modules
///
/// This corresponds to the data in `/proc/modules`.
pub fn modules() -> ProcResult<HashMap<String, KernelModule>> {
    modules_from_read(FileWrapper::open("/proc/modules")?)
}

/// Get a list of the arguments passed to the Linux kernel at boot time
///
/// This corresponds to the data in `/proc/cmdline`
pub fn cmdline() -> ProcResult<Vec<String>> {
    cmdline_from_read(FileWrapper::open("/proc/cmdline")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_statics() {
        println!("{:?}", *TICKS_PER_SECOND);
        println!("{:?}", *KERNEL);
        println!("{:?}", *PAGESIZE);
    }

    #[test]
    fn test_loadavg() {
        let load = LoadAverage::new().unwrap();
        println!("{:?}", load);
    }

    #[test]
    fn test_kernel_config() {
        // TRAVIS
        // we don't have access to the kernel_config on travis, so skip that test there
        match std::env::var("TRAVIS") {
            Ok(ref s) if s == "true" => return,
            _ => {}
        }
        if !Path::new(PROC_CONFIG_GZ).exists() && !Path::new(BOOT_CONFIG).exists() {
            return;
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

    #[test]
    fn test_kernel_stat() {
        let stat = KernelStats::new().unwrap();
        println!("{:#?}", stat);

        // the boottime from KernelStats should match the boottime from /proc/uptime
        let boottime = boot_time_secs().unwrap();

        let diff = (boottime as i32 - stat.btime as i32).abs();
        assert!(diff <= 1);

        let cpuinfo = CpuInfo::new().unwrap();
        assert_eq!(cpuinfo.num_cores(), stat.cpu_time.len());

        // the sum of each individual CPU should be equal to the total cpu entry
        // note: on big machines with 128 cores, it seems that the differences can be rather high,
        // especially when heavily loaded.  So this test tolerates a 6000-tick discrepancy
        // (60 seconds in a 100-tick-per-second kernel)

        let user: u64 = stat.cpu_time.iter().map(|i| i.user).sum();
        let nice: u64 = stat.cpu_time.iter().map(|i| i.nice).sum();
        let system: u64 = stat.cpu_time.iter().map(|i| i.system).sum();
        assert!(
            (stat.total.user as i64 - user as i64).abs() < 6000,
            "sum:{} total:{} diff:{}",
            stat.total.user,
            user,
            stat.total.user - user
        );
        assert!(
            (stat.total.nice as i64 - nice as i64).abs() < 6000,
            "sum:{} total:{} diff:{}",
            stat.total.nice,
            nice,
            stat.total.nice - nice
        );
        assert!(
            (stat.total.system as i64 - system as i64).abs() < 6000,
            "sum:{} total:{} diff:{}",
            stat.total.system,
            system,
            stat.total.system - system
        );

        let diff = stat.total.idle as i64 - (stat.cpu_time.iter().map(|i| i.idle).sum::<u64>() as i64).abs();
        assert!(diff < 1000, "idle time difference too high: {}", diff);
    }

    #[test]
    fn test_vmstat() {
        let stat = vmstat().unwrap();
        println!("{:?}", stat);
    }

    #[test]
    fn test_modules() {
        let mods = modules().unwrap();
        for module in mods.values() {
            println!("{:?}", module);
        }
    }

    #[test]
    fn tests_tps() {
        let tps = ticks_per_second();
        println!("{} ticks per second", tps);
    }

    #[test]
    fn test_cmdline() {
        let cmdline = cmdline().unwrap();

        for argument in cmdline {
            println!("{}", argument);
        }
    }

    /// Test that our error type can be easily used with the `failure` crate
    #[test]
    fn test_failure() {
        fn inner() -> Result<(), failure::Error> {
            let _load = crate::LoadAverage::new()?;
            Ok(())
        }
        let _ = inner();

        fn inner2() -> Result<(), failure::Error> {
            let proc = crate::process::Process::new(1)?;
            let _io = proc.maps()?;
            Ok(())
        }

        let _ = inner2();
        // Unwrapping this failure should produce a message that looks like:
        // thread 'tests::test_failure' panicked at 'called `Result::unwrap()` on an `Err` value: PermissionDenied(Some("/proc/1/maps"))', src/libcore/result.rs:997:5
    }

    /// Test that an ESRCH error gets mapped into a ProcError::NotFound
    #[test]
    fn test_esrch() {
        let mut command = std::process::Command::new("sleep")
            .arg("10000")
            .spawn()
            .expect("Failed to start sleep");
        let p = crate::process::Process::new(command.id() as i32).expect("Failed to create Process");
        command.kill().expect("Failed to kill sleep");
        command.wait().expect("Failed to wait for sleep");
        let e = p.stat().unwrap_err();
        println!("{:?}", e);

        assert!(matches!(e, ProcError::NotFound(_)));
    }
}
