//! Global kernel info / tuning miscellaneous stuff
//!
//! The files in this directory can be used to tune and monitor miscellaneous
//! and general things in the operation of the Linux kernel.

use std::cmp;
use std::collections::HashSet;
use std::str::FromStr;

use bitflags::bitflags;

use crate::{read_value, write_value, ProcError, ProcResult, KERNEL};

pub mod keys;
pub mod random;

/// Represents a kernel version, in major.minor.release version.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
    pub patch: u16,
}

impl Version {
    pub fn new(major: u8, minor: u8, patch: u16) -> Version {
        Version { major, minor, patch }
    }

    /// Returns the kernel version of the currently running kernel.
    ///
    /// This is taken from `/proc/sys/kernel/osrelease`;
    pub fn current() -> ProcResult<Self> {
        read_value("/proc/sys/kernel/osrelease")
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
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, &'static str> {
        let pos = s.find(|c: char| c != '.' && !c.is_ascii_digit());
        let kernel = if let Some(pos) = pos {
            let (s, _) = s.split_at(pos);
            s
        } else {
            s
        };
        let mut kernel_split = kernel.split('.');

        let major = kernel_split.next().ok_or("Missing major version component")?;
        let minor = kernel_split.next().ok_or("Missing minor version component")?;
        let patch = kernel_split.next().ok_or("Missing patch version component")?;

        let major = major.parse().map_err(|_| "Failed to parse major version")?;
        let minor = minor.parse().map_err(|_| "Failed to parse minor version")?;
        let patch = patch.parse().map_err(|_| "Failed to parse patch version")?;

        Ok(Version { major, minor, patch })
    }
}

impl FromStr for Version {
    type Err = &'static str;

    /// Parses a kernel version string, in major.minor.release syntax.
    ///
    /// Note that any extra information (stuff after a dash) is ignored.
    ///
    /// # Example
    ///
    /// ```
    /// # use procfs::KernelVersion;
    /// let a: KernelVersion = "3.16.0-6-amd64".parse().unwrap();
    /// let b = KernelVersion::new(3, 16, 0);
    /// assert_eq!(a, b);
    ///
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Version::from_str(s)
    }
}

impl cmp::Ord for Version {
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

impl cmp::PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(&other))
    }
}

/// Represents a kernel type
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Type {
    pub sysname: String,
}

impl Type {
    pub fn new(sysname: String) -> Type {
        Type { sysname }
    }

    /// Read the kernel type from current running kernel
    ///
    /// Defined in `include/linux/uts.h` as UTS_SYSNAME, default is "Linux".
    /// The file is located at `/proc/sys/kernel/ostype`.
    pub fn current() -> ProcResult<Self> {
        read_value("/proc/sys/kernel/ostype")
    }
}

impl FromStr for Type {
    type Err = &'static str;

    /// Parse a kernel type string
    ///
    /// Notice that in Linux source code, it is defined as a single string
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Type::new(s.to_string()))
    }
}

/// Represents a kernel build information
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BuildInfo {
    pub version: String,
    pub flags: HashSet<String>,
    /// The time when the build was begun
    ///
    /// It defined in `scripts/mkcompile_h`. If `KBUILD_BUILD_TIMESTAMP` was not set, it would be the result of `date`.
    ///
    #[cfg_attr(
        feature = "chrono",
        doc = "See also the [BuildInfo::time()] method to get the time as a `DateTime` object"
    )]
    #[cfg_attr(
        not(feature = "chrono"),
        doc = "If you compile with the optional `chrono` feature, you can use the `starttime()` method to get the time as a `DateTime` object"
    )]
    pub time: String,
}

impl BuildInfo {
    pub fn new(version: &str, flags: HashSet<String>, time: String) -> BuildInfo {
        BuildInfo { version: version.to_string(), flags, time }
    }

    /// Read the kernel build information from current running kernel
    ///
    /// Generated by `scripts/mkcompile_h` when building the kernel.
    /// The file is located at `/proc/sys/kernel/version`.
    pub fn current() -> ProcResult<Self> {
        read_value("/proc/sys/kernel/version")
    }

    // Check if SMP is ON
    pub fn smp(&self) -> bool {
        self.flags.contains("SMP")
    }

    // Check if PREEMPT is ON
    pub fn preempt(&self) -> bool {
        self.flags.contains("PREEMPT")
    }

    // Check if PREEMPTRT is ON
    pub fn preemptrt(&self) -> bool {
        self.flags.contains("PREEMPTRT")
    }

    /// Return version number
    /// 
    /// This would parse number from first digits of version string.
    pub fn version_number(&self) -> ProcResult<u32> {
        let mut version_str = String::new();
        for c in self.version.chars() {
            if c.is_ascii_digit() {
                version_str.push(c);
            } else {
                break;
            }
        }
        let version_number: u32 = version_str.parse().map_err(|_| "Failed to parse version number")?;
        Ok(version_number)
    }

    /// Parse time string to `DateTime` object
    ///
    /// This function may fail as TIMESTAMP can be various formats.
    #[cfg(feature = "chrono")]
    pub fn time(&self) -> ProcResult<chrono::DateTime<chrono::Local>> {
        let dt = chrono::DateTime::parse_from_str(&format!("{} +0000", &self.time), "%a %b %d %H:%M:%S UTC %Y %z")
            .map_err(|_| "Failed to parse kernel build time")?;
        Ok(dt.with_timezone(&chrono::Local))
    }
}

impl FromStr for BuildInfo {
    type Err = &'static str;

    /// Parse a kernel build information string
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut version= String::new();
        let mut flags: HashSet<String> = HashSet::new();
        let mut time: String = String::new();

        let mut splited = s.split(' ');
        let version_str = splited.next();
        if let Some(version_str) = version_str {
            if version_str.starts_with('#') {
                version.push_str(&version_str[1..]);
            } else {
                return Err("Failed to parse kernel build version");
            }
        } else {
            return Err("Failed to parse kernel build version");
        }

        for s in &mut splited {
            if s.chars().all(char::is_uppercase) {
                flags.insert(s.to_string());
            } else {
                time.push_str(s);
                time.push(' ');
                break;
            }
        }
        let remains: Vec<&str> = splited.collect();
        time.push_str(&remains.join(" "));

        Ok(BuildInfo{version, flags, time})
    }
}

/// Returns the maximum process ID number.
///
/// This is taken from `/proc/sys/kernel/pid_max`.
///
/// # Example
///
/// ```
/// let pid_max = procfs::sys::kernel::pid_max().unwrap();
///
/// let pid = 42; // e.g. from user input, CLI args, etc.
///
/// if pid > pid_max {
///     eprintln!("bad process ID: {}", pid)
/// } else {
///     println!("good process ID: {}", pid);
/// }
/// ```
pub fn pid_max() -> ProcResult<i32> {
    read_value("/proc/sys/kernel/pid_max")
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
/// Represents the data from `/proc/sys/kernel/sem`
pub struct SemaphoreLimits {
    /// The maximum semaphores per semaphore set
    pub semmsl: u64,
    /// A system-wide limit on the number of semaphores in all semaphore sets
    pub semmns: u64,
    /// The maximum number of operations that may be specified in a semop(2) call
    pub semopm: u64,
    /// A system-wide limit on the maximum number of semaphore identifiers
    pub semmni: u64,
}

impl SemaphoreLimits {
    pub fn new() -> ProcResult<Self> {
        read_value("/proc/sys/kernel/sem")
    }

    fn from_str(s: &str) -> Result<Self, &'static str> {
        let mut s = s.split_ascii_whitespace();

        let semmsl = s.next().ok_or("Missing SEMMSL")?;
        let semmns = s.next().ok_or("Missing SEMMNS")?;
        let semopm = s.next().ok_or("Missing SEMOPM")?;
        let semmni = s.next().ok_or("Missing SEMMNI")?;

        let semmsl = semmsl.parse().map_err(|_| "Failed to parse SEMMSL")?;
        let semmns = semmns.parse().map_err(|_| "Failed to parse SEMMNS")?;
        let semopm = semopm.parse().map_err(|_| "Failed to parse SEMOPM")?;
        let semmni = semmni.parse().map_err(|_| "Failed to parse SEMMNI")?;

        Ok(SemaphoreLimits {
            semmsl,
            semmns,
            semopm,
            semmni,
        })
    }
}

impl FromStr for SemaphoreLimits {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SemaphoreLimits::from_str(s)
    }
}

/// Returns the system-wide limit on the total number of pages of System V shared memory
///
/// This is taken from `/proc/sys/kernel/shmall`
pub fn shmall() -> ProcResult<u64> {
    read_value("/proc/sys/kernel/shmall")
}

/// Returns the limit on the maximum (System V IPC) shared memory segment size that can be created.
/// The value defaults to SHMMAX
///
/// See also [set_shmmax](crate::sys::kernel::set_shmmax)
///
/// This is taken from `/proc/sys/kernel/shmmax`
pub fn shmmax() -> ProcResult<u64> {
    read_value("/proc/sys/kernel/shmmax")
}

/// Sets the limit on the maximum (System V IPC) shared memory segment size.
///
/// See also [shmmax](crate::sys::kernel::shmmax)
pub fn set_shmmax(new_value: u64) -> ProcResult<()> {
    write_value("/proc/sys/kernel/shmmax", new_value)
}

/// Returns the system-wide maximum number of System V shared memory segments that can be created
///
/// This is taken from `/proc/sys/kernel/shmmni`
pub fn shmmni() -> ProcResult<u64> {
    read_value("/proc/sys/kernel/shmmni")
}

bitflags! {
    /// Flags representing allowed sysrq functions
    pub struct AllowedFunctions : u16 {
        /// Enable control of console log level
        const ENABLE_CONTROL_LOG_LEVEL = 2;
        /// Enable control of keyboard (SAK, unraw)
        const ENABLE_CONTROL_KEYBOARD = 4;
        /// Enable debugging dumps of processes etc
        const ENABLE_DEBUGGING_DUMPS = 8;
        /// Enable sync command
        const ENABLE_SYNC_COMMAND = 16;
        /// Enable remound read-only
        const ENABLE_REMOUNT_READ_ONLY = 32;
        /// Enable signaling of processes (term, kill, oom-kill)
        const ENABLE_SIGNALING_PROCESSES = 64;
        /// Allow reboot/poweroff
        const ALLOW_REBOOT_POWEROFF = 128;
        /// Allow nicing of all real-time tasks
        const ALLOW_NICING_REAL_TIME_TASKS = 256;
    }
}

/// Values controlling functions allowed to be invoked by the SysRq key
///
/// To construct this enum, see [sysrq](crate::sys::kernel::sysrq)
#[derive(Copy, Clone, Debug)]
pub enum SysRq {
    /// Disable sysrq completely
    Disable,
    /// Enable all functions of sysrq
    Enable,
    /// Bitmask of allowed sysrq functions
    AllowedFunctions(AllowedFunctions),
}

impl SysRq {
    fn to_number(self) -> u16 {
        match self {
            SysRq::Disable => 0,
            SysRq::Enable => 1,
            SysRq::AllowedFunctions(allowed) => allowed.bits,
        }
    }

    fn from_str(s: &str) -> ProcResult<Self> {
        match s.parse::<u16>()? {
            0 => Ok(SysRq::Disable),
            1 => Ok(SysRq::Enable),
            x => match AllowedFunctions::from_bits(x) {
                Some(allowed) => Ok(SysRq::AllowedFunctions(allowed)),
                None => Err("Invalid value".into()),
            },
        }
    }
}

impl FromStr for SysRq {
    type Err = ProcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SysRq::from_str(s)
    }
}

/// Return functions allowed to be invoked by the SysRq key
///
/// This is taken from `/proc/sys/kernel/sysrq`
pub fn sysrq() -> ProcResult<SysRq> {
    read_value("/proc/sys/kernel/sysrq")
}

/// Set functions allowed to be invoked by the SysRq key
pub fn set_sysrq(new: SysRq) -> ProcResult<()> {
    write_value("/proc/sys/kernel/sysrq", new.to_number())
}

/// The minimum value that can be written to `/proc/sys/kernel/threads-max` on Linux 4.1 or later
pub const THREADS_MIN: u32 = 20;
/// The maximum value that can be written to `/proc/sys/kernel/threads-max` on Linux 4.1 or later
pub const THREADS_MAX: u32 = 0x3fff_ffff;

/// Returns the system-wide limit on the number of threads (tasks) that can be created on the system.
///
/// This is taken from `/proc/sys/kernel/threads-max`
pub fn threads_max() -> ProcResult<u32> {
    read_value("/proc/sys/kernel/threads-max")
}

/// Sets the system-wide limit on the number of threads (tasks) that can be created on the system.
///
/// Since Linux 4.1, this value is bounded, and must be in the range [THREADS_MIN]..=[THREADS_MAX].
/// This function will return an error if that is not the case.
pub fn set_threads_max(new_limit: u32) -> ProcResult<()> {
    if let Ok(kernel) = *KERNEL {
        if kernel.major >= 4 && kernel.minor >= 1 && !(THREADS_MIN <= new_limit && new_limit <= THREADS_MAX) {
            return Err(ProcError::Other(format!(
                "{} is outside the THREADS_MIN..=THREADS_MAX range",
                new_limit
            )));
        }
    }

    write_value("/proc/sys/kernel/threads-max", new_limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let a = Version::from_str("3.16.0-6-amd64").unwrap();
        let b = Version::new(3, 16, 0);
        assert_eq!(a, b);

        let a = Version::from_str("3.16.0").unwrap();
        let b = Version::new(3, 16, 0);
        assert_eq!(a, b);

        let a = Version::from_str("3.16.0_1").unwrap();
        let b = Version::new(3, 16, 0);
        assert_eq!(a, b);
    }

    #[test]
    fn test_type() {
        let a = Type::from_str("Linux").unwrap();
        assert_eq!(a.sysname, "Linux");
    }

    #[test]
    fn test_build_info() {
        let a = BuildInfo::from_str("#1 SMP PREEMPT Thu Sep 30 15:29:01 UTC 2021").unwrap();
        let mut flags: HashSet<String> = HashSet::new();
        flags.insert("SMP".to_string());
        flags.insert("PREEMPT".to_string());
        assert_eq!(a.version, "1");
        assert_eq!(a.version_number().unwrap(), 1);
        assert_eq!(a.flags, flags);
        assert!(a.smp());
        assert!(a.preempt());
        assert!(!a.preemptrt());
        assert_eq!(a.time, "Thu Sep 30 15:29:01 UTC 2021");
        #[cfg(feature = "chrono")]
        let _ = a.time().unwrap();

        let b = BuildInfo::from_str("#1 Thu Sep 30 15:29:01 UTC 2021").unwrap();
        let flags: HashSet<String> = HashSet::new();
        assert_eq!(b.version, "1");
        assert_eq!(b.version_number().unwrap(), 1);
        assert_eq!(b.flags, flags);
        assert_eq!(b.time, "Thu Sep 30 15:29:01 UTC 2021");
        assert!(!b.smp());
        assert!(!b.preempt());
        assert!(!b.preemptrt());
        #[cfg(feature = "chrono")]
        let _ = b.time().unwrap();

        let c = BuildInfo::from_str("#21~20.04.1-Ubuntu SMP Mon Oct 11 18:54:28 UTC 2021").unwrap();
        let mut flags: HashSet<String> = HashSet::new();
        flags.insert("SMP".to_string());
        assert_eq!(c.version, "21~20.04.1-Ubuntu");
        assert_eq!(c.version_number().unwrap(), 21);
        assert_eq!(c.flags, flags);
        assert_eq!(c.time, "Mon Oct 11 18:54:28 UTC 2021");
        assert!(c.smp());
        assert!(!c.preempt());
        assert!(!c.preemptrt());
        #[cfg(feature = "chrono")]
        let _ = c.time().unwrap();
    }

    #[test]
    fn test_current() {
        let _ = Version::current().unwrap();
        let _ = Type::current().unwrap();
        let _ = BuildInfo::current().unwrap();
    }

    #[test]
    fn test_pid_max() {
        assert!(pid_max().is_ok());
    }

    #[test]
    fn test_semaphore_limits() {
        // Note that the below string has tab characters in it. Make sure to not remove them.
        let a = SemaphoreLimits::from_str("32000	1024000000	500	32000").unwrap();
        let b = SemaphoreLimits {
            semmsl: 32_000,
            semmns: 1_024_000_000,
            semopm: 500,
            semmni: 32_000,
        };
        assert_eq!(a, b);

        let a = SemaphoreLimits::from_str("1");
        assert!(a.is_err() && a.err().unwrap() == "Missing SEMMNS");

        let a = SemaphoreLimits::from_str("1 string 500 3200");
        assert!(a.is_err() && a.err().unwrap() == "Failed to parse SEMMNS");
    }

    #[test]
    fn test_sem() {
        let _ = SemaphoreLimits::new().unwrap();
    }
    #[test]
    fn test_shmall() {
        let _ = shmall().unwrap();
    }

    #[test]
    fn test_shmmax() {
        let _ = shmmax().unwrap();
    }

    #[test]
    fn test_shmmni() {
        let _ = shmmni().unwrap();
    }

    #[test]
    fn test_sysrq() {
        let sys_rq = sysrq().unwrap();
        println!("{:?}", sys_rq)
    }

    #[test]
    fn test_threads_max() {
        let _ = threads_max().unwrap();
    }
}
