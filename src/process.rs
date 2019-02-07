use super::*;

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
#[cfg(unix)]
use std::os::linux::fs::MetadataExt;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

// provide a type-compatible st_uid for windows
#[cfg(windows)]
trait FakeMedatadataExt {
    fn st_uid(&self) -> u32;
}
#[cfg(windows)]
impl FakeMedatadataExt for std::fs::Metadata {
    fn st_uid(&self) -> u32 {
        panic!()
    }
}

bitflags! {
    pub struct StatFlags: u32 {
        /// I am an IDLE thread
        const PF_IDLE = 0x0000_0002;
        /// Getting shut down
        const PF_EXITING = 0x0000_0004;
        /// PI exit done on shut down
        const PF_EXITPIDONE = 0x0000_0008;
        /// I'm a virtual CPU
        const PF_VCPU = 0x0000_0010;
        /// I'm a workqueue worker
        const PF_WQ_WORKER = 0x0000_0020;
        /// Forked but didn't exec
        const PF_FORKNOEXEC = 0x0000_0040;
        /// Process policy on mce errors;
        const PF_MCE_PROCESS = 0x0000_0080;
        /// Used super-user privileges
        const PF_SUPERPRIV = 0x0000_0100;
        /// Dumped core
        const PF_DUMPCORE = 0x0000_0200;
        /// Killed by a signal
        const PF_SIGNALED = 0x0000_0400;
        ///Allocating memory
        const PF_MEMALLOC = 0x0000_0800;
        /// set_user() noticed that RLIMIT_NPROC was exceeded
        const PF_NPROC_EXCEEDED = 0x0000_1000;
        /// If unset the fpu must be initialized before use
        const PF_USED_MATH = 0x0000_2000;
         /// Used async_schedule*(), used by module init
        const PF_USED_ASYNC = 0x0000_4000;
        ///  This thread should not be frozen
        const PF_NOFREEZE = 0x0000_8000;
        /// Frozen for system suspend
        const PF_FROZEN = 0x0001_0000;
        //// I am kswapd
        const PF_KSWAPD = 0x0002_0000;
        /// All allocation requests will inherit GFP_NOFS
        const PF_MEMALLOC_NOFS = 0x0004_0000;
        /// All allocation requests will inherit GFP_NOIO
        const PF_MEMALLOC_NOIO = 0x0008_0000;
        /// Throttle me less: I clean memory
        const PF_LESS_THROTTLE = 0x0010_0000;
        /// I am a kernel thread
        const PF_KTHREAD = 0x0020_0000;
        /// Randomize virtual address space
        const PF_RANDOMIZE = 0x0040_0000;
        /// Allowed to write to swap
        const PF_SWAPWRITE = 0x0080_0000;
        /// Userland is not allowed to meddle with cpus_allowed
        const PF_NO_SETAFFINITY = 0x0400_0000;
        /// Early kill for mce process policy
        const PF_MCE_EARLY = 0x0800_0000;
        /// Thread belongs to the rt mutex tester
        const PF_MUTEX_TESTER = 0x2000_0000;
        /// Freezer should not count it as freezable
        const PF_FREEZER_SKIP = 0x4000_0000;
        /// This thread called freeze_processes() and should not be frozen
        const PF_SUSPEND_TASK = 0x8000_0000;

    }
}
bitflags! {

    pub struct CoredumpFlags: u32 {
        const ANONYMOUS_PRIVATE_MAPPINGS = 0x01;
        const ANONYMOUS_SHARED_MAPPINGS = 0x02;
        const FILEBACKED_PRIVATE_MAPPINGS = 0x04;
        const FILEBACKED_SHARED_MAPPINGS = 0x08;
        const ELF_HEADERS = 0x10;
        const PROVATE_HUGEPAGES = 0x20;
        const SHARED_HUGEPAGES = 0x40;
        const PRIVATE_DAX_PAGES = 0x80;
        const SHARED_DAX_PAGES = 0x100;
    }
}

bitflags! {
    pub struct NFSServerCaps: u32 {

        const NFS_CAP_READDIRPLUS = (1 << 0);
        const NFS_CAP_HARDLINKS = (1 << 1);
        const NFS_CAP_SYMLINKS = (1 << 2);
        const NFS_CAP_ACLS = (1 << 3);
        const NFS_CAP_ATOMIC_OPEN = (1 << 4);
        const NFS_CAP_LGOPEN = (1 << 5);
        const NFS_CAP_FILEID = (1 << 6);
        const NFS_CAP_MODE = (1 << 7);
        const NFS_CAP_NLINK = (1 << 8);
        const NFS_CAP_OWNER = (1 << 9);
        const NFS_CAP_OWNER_GROUP = (1 << 10);
        const NFS_CAP_ATIME = (1 << 11);
        const NFS_CAP_CTIME = (1 << 12);
        const NFS_CAP_MTIME = (1 << 13);
        const NFS_CAP_POSIX_LOCK = (1 << 14);
        const NFS_CAP_UIDGID_NOMAP = (1 << 15);
        const NFS_CAP_STATEID_NFSV41 = (1 << 16);
        const NFS_CAP_ATOMIC_OPEN_V1 = (1 << 17);
        const NFS_CAP_SECURITY_LABEL = (1 << 18);
        const NFS_CAP_SEEK = (1 << 19);
        const NFS_CAP_ALLOCATE = (1 << 20);
        const NFS_CAP_DEALLOCATE = (1 << 21);
        const NFS_CAP_LAYOUTSTATS = (1 << 22);
        const NFS_CAP_CLONE = (1 << 23);
        const NFS_CAP_COPY = (1 << 24);
        const NFS_CAP_OFFLOAD_CANCEL = (1 << 25);
    }
}

//impl<'a, 'b, T> ProcFrom<&'b mut T> for u32 where T: Iterator<Item=&'a str> + Sized, 'a: 'b {
//    fn from(i: &'b mut T) -> u32 {
//        let s = i.next().unwrap();
//        u32::from_str_radix(s, 10).unwrap()
//    }
//}

fn from_iter<'a, I, U>(i: I) -> U
where
    I: IntoIterator<Item = &'a str>,
    U: FromStr,
{
    let mut iter = i.into_iter();
    let val = expect!(iter.next(), "Missing iterator next item");
    match FromStr::from_str(val) {
        Ok(u) => u,
        Err(..) => panic!("Failed to convert".to_string()),
    }
}

//impl<'a> ProcFrom<&'a str> for u32 {
//    fn from(s: &str) -> Self {
//        u32::from_str_radix(s, 10).unwrap()
//    }
//}

//fn from_iter<'a, I: Iterator<Item=&'a str>>(i: &mut I) -> u32 {
//    u32::from_str_radix(i.next().unwrap(), 10).unwrap()
//}

/// Represents the state of a process.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProcState {
    /// Running (R)
    Running,
    /// Sleeping in an interruptible wait (S)
    Sleeping,
    /// Waiting in uninterruptible disk sleep (D)
    Waiting,
    /// Zombie (Z)
    Zombie,
    /// Stopped (on a signal) (T)
    ///
    /// Or before Linux 2.6.33, trace stopped
    Stopped,
    /// Tracing stop (t) (Linux 2.6.33 onward)
    Tracing,
    /// Dead (X)
    Dead,
    /// Wakekill (K) (Linux 2.6.33 to 3.13 only)
    Wakekill,
    /// Waking (W) (Linux 2.6.33 to 3.13 only)
    Waking,
    /// Parked (P) (Linux 3.9 to 3.13 only)
    Parked,
}

impl ProcState {
    pub fn from_char(c: char) -> Option<ProcState> {
        match c {
            'R' => Some(ProcState::Running),
            'S' => Some(ProcState::Sleeping),
            'D' => Some(ProcState::Waiting),
            'Z' => Some(ProcState::Zombie),
            'T' => Some(ProcState::Stopped),
            't' => Some(ProcState::Tracing),
            'X' | 'x' => Some(ProcState::Dead),
            'K' => Some(ProcState::Wakekill),
            'W' => Some(ProcState::Waking),
            'P' => Some(ProcState::Parked),
            _ => None,
        }
    }
}

impl FromStr for ProcState {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<ProcState, &'static str> {
        ProcState::from_char(expect!(s.chars().next(), "empty string")).ok_or("Failed to convert")
    }
}

//impl<'a, 'b, T> ProcFrom<&'b mut T> for ProcState where T: Iterator<Item=&'a str>, 'a: 'b {
//    fn from(s: &'b mut T) -> ProcState {
//        ProcState::from_str(s.next().unwrap()).unwrap()
//    }
//}

/// Status information about the process, based on the `/proc/<pid>/stat` file.
///
/// To construct one of these structures, you have to first create a [Process].
///
/// Not all fields are available in every kernel.  These fields have `Option<T>` types.
#[derive(Debug, Clone)]
pub struct Stat {
    /// The process ID.
    pub pid: i32,
    /// The filename of the executable, in parentheses.
    ///
    /// This is visible whether or not the executable is swapped out.
    pub comm: String,
    /// Process State.
    ///
    /// See [state()](#method.state) to get the process state as an enum.
    pub state: char,
    /// The PID of the parent of this process.
    pub ppid: i32,
    /// The process group ID of the process.
    pub pgrp: i32,
    /// The session ID of the process.
    pub session: i32,
    /// The controlling terminal of the process.
    ///
    /// The minor device number is contained in the combination of bits 31 to 20 and  7  to  0;
    /// the major device number is in bits 15 to 8.
    ///
    /// See [tty_nr()](#method.tty_nr) to get this value decoded into a (major, minor) tuple
    pub tty_nr: i32,
    /// The ID of the foreground process group of the controlling terminal of the process.
    pub tpgid: i32,
    /// The kernel flags  word of the process.
    ///
    /// For bit meanings, see the PF_* defines in  the  Linux  kernel  source  file
    /// [`include/linux/sched.h`](https://github.com/torvalds/linux/blob/master/include/linux/sched.h).
    ///
    /// See [flags()](#method.flags) to get a [`StatFlags`](struct.StatFlags.html) bitfield object.
    pub flags: u32,
    /// The number of minor faults the process has made which have not required loading a memory
    /// page from disk.
    pub minflt: u64,
    /// The number of minor faults that the process's waited-for children have made.
    pub cminflt: u64,
    /// The number of major faults the process has made which have required loading a memory page
    /// from disk.
    pub majflt: u64,
    /// The number of major faults that the process's waited-for children have made.
    pub cmajflt: u64,
    /// Amount of time that this process has been scheduled in user mode, measured in clock ticks
    /// (divide by [`ticks_per_second()`].
    ///
    /// This includes guest time, guest_time (time spent running a virtual CPU, see below), so that
    /// applications that are not aware of the guest time field  do not lose that time from their
    /// calculations.
    pub utime: u64,
    /// Amount of time that this process has been scheduled in kernel mode, measured in clock ticks
    /// (divide by [`ticks_per_second()`]).
    pub stime: u64,

    /// Amount  of  time  that  this  process's  waited-for  children  have  been  scheduled  in
    /// user  mode,  measured  in clock ticks (divide by [`ticks_per_second()`]).
    ///
    /// This includes guest time, cguest_time (time spent running a virtual CPU, see below).
    pub cutime: i64,

    /// Amount of time that this process's waited-for  children  have  been  scheduled  in  kernel
    /// mode,  measured  in  clock  ticks  (divide  by [`ticks_per_second()`]).
    pub cstime: i64,
    /// For processes running a real-time scheduling policy (policy below; see sched_setscheduler(2)),
    /// this is the negated scheduling priority, minus one;
    ///
    /// That is, a number in the range -2 to -100,
    /// corresponding to real-time priority orities  1  to 99.  For processes running under a non-real-time
    /// scheduling policy, this is the raw nice value (setpriority(2)) as represented in the kernel.
    /// The kernel stores nice values as numbers in the range 0 (high) to 39  (low),  corresponding
    /// to the user-visible nice range of -20 to 19.
    /// (This explanation is for Linux 2.6)
    ///
    /// Before Linux 2.6, this was a scaled value based on the scheduler weighting given to this process.
    pub priority: i64,
    /// The nice value (see `setpriority(2)`), a value in the range 19 (low priority) to -20 (high priority).
    pub nice: i64,
    /// Number  of  threads in this process (since Linux 2.6).  Before kernel 2.6, this field was
    /// hard coded to 0 as a placeholder for an earlier removed field.
    pub num_threads: i64,
    /// The time in jiffies before the next SIGALRM is sent to the process due to an interval
    /// timer.
    ///
    /// Since kernel 2.6.17, this  field is no longer maintained, and is hard coded as 0.
    pub itrealvalue: i64,
    /// The time the process started after system boot.
    ///
    /// In kernels before Linux 2.6, this value was expressed in  jiffies.  Since  Linux 2.6, the
    /// value is expressed in clock ticks (divide by `sysconf(_SC_CLK_TCK)`).
    pub starttime: i64,
    /// Virtual memory size in bytes.
    pub vsize: u64,
    /// Resident Set Size: number of pages the process has in real memory.
    ///
    /// This is just the pages which count toward text,  data,  or stack space.
    /// This does not include pages which have not been demand-loaded in, or which are swapped out.
    pub rss: i64,
    /// Current soft limit in bytes on the rss of the process; see the description of RLIMIT_RSS in
    /// getrlimit(2).
    pub rsslim: u64,
    /// The address above which program text can run.
    pub startcode: u64,
    /// The address below which program text can run.
    pub endcode: u64,
    /// The address of the start (i.e., bottom) of the stack.
    pub startstack: u64,
    /// The current value of ESP (stack pointer), as found in the kernel stack page for the
    /// process.
    pub kstkesp: u64,
    /// The current EIP (instruction pointer).
    pub kstkeip: u64,
    /// The  bitmap of pending signals, displayed as a decimal number.  Obsolete, because it does
    /// not provide information on real-time signals; use `/proc/<pid>/status` instead.
    pub signal: u64,
    /// The bitmap of blocked signals, displayed as a decimal number.  Obsolete, because it does
    /// not provide information on  real-time signals; use `/proc/<pid>/status` instead.
    pub blocked: u64,
    /// The  bitmap of ignored signals, displayed as a decimal number.  Obsolete, because it does
    /// not provide information on real-time signals; use `/proc/<pid>/status` instead.
    pub sigignore: u64,
    /// The bitmap of caught signals, displayed as a decimal number.  Obsolete, because it does not
    /// provide information  on  real-time signals; use `/proc/<pid>/status` instead.
    pub sigcatch: u64,
    /// This  is  the  "channel"  in which the process is waiting.  It is the address of a location
    /// in the kernel where the process is sleeping.  The corresponding symbolic name can be found in
    /// `/proc/<pid>/wchan`.
    pub wchan: u64,
    /// Number of pages swapped **(not maintained)**.
    pub nswap: u64,
    /// Cumulative nswap for child processes **(not maintained)**.
    pub cnswap: u64,
    /// Signal to be sent to parent when we die.
    ///
    /// (since Linux 2.1.22)
    pub exit_signal: Option<i32>,
    /// CPU number last executed on.
    ///
    /// (since Linux 2.2.8)
    pub processor: Option<i32>,
    /// Real-time scheduling priority
    ///
    ///  Real-time scheduling priority, a number in the range 1 to 99 for processes scheduled under a real-time policy, or 0, for non-real-time processes
    ///
    /// (since Linux 2.5.19)
    pub rt_priority: Option<u32>,
    /// Scheduling policy (see sched_setscheduler(2)).
    ///
    /// Decode using the `SCHED_*` constants in `linux/sched.h`.
    ///
    /// (since Linux 2.5.19)
    pub policy: Option<u32>,
    /// Aggregated block I/O delays, measured in clock ticks (centiseconds).
    ///
    /// (since Linux 2.6.18)
    pub delayacct_blkio_ticks: Option<u64>,
    /// Guest time of the process (time spent running a virtual CPU for a guest operating system),
    /// measured in clock ticks (divide by [`ticks_per_second()`])
    ///
    /// (since Linux 2.6.24)
    pub guest_time: Option<u32>,
    /// Guest time of the process's children, measured in clock ticks (divide by
    /// [`ticks_per_second()`]).
    ///
    /// (since Linux 2.6.24)
    pub cguest_time: Option<u32>,
    /// Address above which program initialized and uninitialized (BSS) data are placed.
    ///
    /// (since Linux 3.3)
    pub start_data: Option<usize>,
    /// Address below which program initialized and uninitialized (BSS) data are placed.
    ///
    /// (since Linux 3.3)
    pub end_data: Option<usize>,
    /// Address above which program heap can be expanded with brk(2).
    ///
    /// (since Linux 3.3)
    pub start_brk: Option<usize>,
    /// Address above which program command-line arguments (argv) are placed.
    ///
    /// (since Linux 3.5)
    pub arg_start: Option<usize>,
    /// Address below program command-line arguments (argv) are placed.
    ///
    /// (since Linux 3.5)
    pub arg_end: Option<usize>,
    /// Address above which program environment is placed.
    ///
    /// (since Linux 3.5)
    pub env_start: Option<usize>,
    /// Address below which program environment is placed.
    ///
    /// (since Linux 3.5)
    pub env_end: Option<usize>,
    /// The thread's exit status in the form reported by waitpid(2).
    ///
    /// (since Linux 3.5)
    pub exit_code: Option<i32>,
}

/// This struct contains I/O statistics for the process, built from `/proc/<pid>/io`
///
/// To construct this structure, see [Process::io()].
///
/// #  Note
///
/// In the current implementation, things are a bit racy on 32-bit systems: if process A
/// reads process B's `/proc/<pid>/io` while process  B is updating one of these 64-bit
/// counters, process A could see an intermediate result.
#[derive(Debug)]
pub struct Io {
    /// Characters read
    ///
    /// The number of bytes which this task has caused to be read from storage.  This is simply the
    /// sum of bytes which this process passed to read(2)  and  similar system calls.  It includes
    /// things such as terminal I/O and is unaffected by whether or not actual physical disk I/O
    /// was required (the read might have been satisfied from pagecache).
    pub rchar: u64,

    /// characters written
    ///
    /// The number of bytes which this task has caused, or shall cause to be written to disk.
    /// Similar caveats apply here as with rchar.
    pub wchar: u64,
    /// read syscalls
    ///
    /// Attempt to count the number of write I/O operations—that is, system calls such as write(2)
    /// and pwrite(2).
    pub syscr: u64,
    /// write syscalls
    ///
    /// Attempt to count the number of write I/O operations—that is, system calls such as write(2)
    /// and pwrite(2).
    pub syscw: u64,
    /// bytes read
    ///
    /// Attempt to count the number of bytes which this process really did cause to be fetched from
    /// the storage layer.  This is accurate  for block-backed filesystems.
    pub read_bytes: u64,
    /// bytes written
    ///
    /// Attempt to count the number of bytes which this process caused to be sent to the storage layer.
    pub write_bytes: u64,
    /// Cancelled write bytes.
    ///
    /// The  big inaccuracy here is truncate.  If a process writes 1MB to a file and then deletes
    /// the file, it will in fact perform no write‐ out.  But it will have been accounted as having
    /// caused 1MB of write.  In other words: this field represents the number of bytes which this
    /// process caused to not happen, by truncating pagecache.  A task can cause "negative" I/O too.
    /// If this task truncates some dirty pagecache, some I/O which another task has been accounted
    /// for (in its write_bytes) will not be happening.
    pub cancelled_write_bytes: u64,
}

/// Mount information from `/proc/<pid>/mountstats`.
///
/// # Example:
///
/// ```
/// # use procfs::Process;
/// let stats = Process::myself().unwrap().mountstats().unwrap();
///
/// for mount in stats {
///     println!("{} mounted on {} wth type {}",
///         mount.device.unwrap_or("??".to_owned()),
///         mount.mount_point.display(),
///         mount.fs
///     );
/// }
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct MountStat {
    /// The name of the mounted device
    pub device: Option<String>,
    /// The mountpoint within the filesystem tree
    pub mount_point: PathBuf,
    /// The filesystem type
    pub fs: String,
    /// If the mount is NFS, this will contain various NFS statistics
    pub statistics: Option<MountNFSStatistics>,
}

impl MountStat {
    pub fn from_reader<R: io::Read>(r: R) -> Vec<MountStat> {
        use std::io::{BufRead, BufReader};
        use std::path::PathBuf;

        let mut v = Vec::new();

        let bufread = BufReader::new(r);
        let mut lines = bufread.lines();
        while let Some(Ok(line)) = lines.next() {
            if line.starts_with("device ") {
                // line will be of the format:
                // device proc mounted on /proc with fstype proc
                let mut s = line.split_whitespace();

                let device = Some(s.nth(1).unwrap().to_owned());
                let mount_point = PathBuf::from(s.nth(2).unwrap());
                let fs = s.nth(2).unwrap().to_owned();
                let statistics = match s.next() {
                    Some(stats) if stats.starts_with("statvers=") => {
                        Some(MountNFSStatistics::from_lines(&mut lines, &stats[9..]))
                    }
                    _ => None,
                };

                v.push(MountStat {
                    device,
                    mount_point,
                    fs,
                    statistics,
                });
            }
        }

        v
    }
}

/// Only NFS mounts provide additional statistics in `MountStat` entries.
//
// Thank you to Chris Siebenmann for their helpful work in documenting these structures:
// https://utcc.utoronto.ca/~cks/space/blog/linux/NFSMountstatsIndex
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct MountNFSStatistics {
    /// The version of the NFS statistics block.  Either "1.0" or "1.1".
    pub version: String,
    /// The mount options.
    ///
    /// The meaning of these can be found in the manual pages for mount(5) and nfs(5)
    pub opts: Vec<String>,
    /// Duration the NFS mount has been in existence.
    pub age: Duration,
    // * fsc (?)
    // * impl_id (NFSv4): Option<HashMap<String, Some(String)>>
    /// NFS Capabilities.
    ///
    /// See `include/linux/nfs_fs_sb.h`
    ///
    /// Some known values:
    /// * caps: server capabilities.  See [NFSServerCaps].
    /// * wtmult: server disk block size
    /// * dtsize: readdir size
    /// * bsize: server block size
    pub caps: Vec<String>,
    // * nfsv4 (NFSv4): Option<HashMap<String, Some(String)>>
    pub sec: Vec<String>,
    pub events: NFSEventCounter,
    pub bytes: NFSByteCounter,
    // * RPC iostats version:
    // * xprt
    // * per-op statistics
    pub per_op_stats: NFSPerOpStats,
}

impl MountNFSStatistics {
    // Keep reading lines until we get to a blank line
    fn from_lines<B: io::BufRead>(r: &mut io::Lines<B>, statsver: &str) -> MountNFSStatistics {
        use std::iter::Iterator;

        let mut parsing_per_op = false;

        let mut opts: Option<Vec<String>> = None;
        let mut age = None;
        let mut caps = None;
        let mut sec = None;
        let mut bytes = None;
        let mut events = None;
        let mut per_op = HashMap::new();

        while let Some(Ok(line)) = r.next() {
            let line = line.trim();
            if line.trim() == "" {
                break;
            }
            if !parsing_per_op {
                if line.starts_with("opts:") {
                    opts = Some(line[5..].trim().split(',').map(|s| s.to_string()).collect());
                } else if line.starts_with("age:") {
                    age = Some(Duration::from_secs(from_str!(u64, &line[4..].trim())));
                } else if line.starts_with("caps:") {
                    caps = Some(line[5..].trim().split(',').map(|s| s.to_string()).collect());
                } else if line.starts_with("sec:") {
                    sec = Some(line[4..].trim().split(',').map(|s| s.to_string()).collect());
                } else if line.starts_with("bytes:") {
                    bytes = Some(NFSByteCounter::from_str(&line[6..].trim()));
                } else if line.starts_with("events:") {
                    events = Some(NFSEventCounter::from_str(&line[7..].trim()));
                }
                if line == "per-op statistics" {
                    parsing_per_op = true;
                }
            } else {
                let mut split = line.split(':');
                let name = expect!(split.next()).to_string();
                let stats = NFSOperationStat::from_str(expect!(split.next()));
                per_op.insert(name, stats);
            }
        }

        MountNFSStatistics {
            version: statsver.to_string(),
            opts: expect!(opts, "Failed to find opts field in nfs stats"),
            age: expect!(age, "Failed to find age field in nfs stats"),
            caps: expect!(caps, "Failed to find caps field in nfs stats"),
            sec: expect!(sec, "Failed to find sec field in nfs stats"),
            events: expect!(events, "Failed to find events section in nfs stats"),
            bytes: expect!(bytes, "Failed to find bytes section in nfs stats"),
            per_op_stats: per_op,
        }
    }

    /// Attempts to parse the caps= value from the [caps] field.
    pub fn server_caps(&self) -> Option<NFSServerCaps> {
        for data in &self.caps {
            if data.starts_with("caps=0x") {
                let val = from_str!(u32, &data[7..], 16);
                return NFSServerCaps::from_bits(val);
            }
        }
        None
    }
}

/// Represents NFS data from `/proc/<pid>/mountstats` under the section `events`.
///
/// The underlying data structure in the kernel can be found under *fs/nfs/iostat.h* `nfs_iostat`.
/// The fields are documented in the kernel source only under *include/linux/nfs_iostat.h* `enum
/// nfs_stat_eventcounters`.
#[derive(Debug, Copy, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct NFSEventCounter {
    inode_revalidate: libc::c_ulong,
    deny_try_revalidate: libc::c_ulong,
    data_invalidate: libc::c_ulong,
    attr_invalidate: libc::c_ulong,
    vfs_open: libc::c_ulong,
    vfs_lookup: libc::c_ulong,
    vfs_access: libc::c_ulong,
    vfs_update_page: libc::c_ulong,
    vfs_read_page: libc::c_ulong,
    vfs_read_pages: libc::c_ulong,
    vfs_write_page: libc::c_ulong,
    vfs_write_pages: libc::c_ulong,
    vfs_get_dents: libc::c_ulong,
    vfs_set_attr: libc::c_ulong,
    vfs_flush: libc::c_ulong,
    vfs_fs_sync: libc::c_ulong,
    vfs_lock: libc::c_ulong,
    vfs_release: libc::c_ulong,
    congestion_wait: libc::c_ulong,
    set_attr_trunc: libc::c_ulong,
    extend_write: libc::c_ulong,
    silly_rename: libc::c_ulong,
    short_read: libc::c_ulong,
    short_write: libc::c_ulong,
    delay: libc::c_ulong,
    pnfs_read: libc::c_ulong,
    pnfs_write: libc::c_ulong,
}

impl NFSEventCounter {
    fn from_str(s: &str) -> NFSEventCounter {
        use libc::c_ulong;
        let mut s = s.split_whitespace();
        NFSEventCounter {
            inode_revalidate: from_str!(c_ulong, expect!(s.next())),
            deny_try_revalidate: from_str!(c_ulong, expect!(s.next())),
            data_invalidate: from_str!(c_ulong, expect!(s.next())),
            attr_invalidate: from_str!(c_ulong, expect!(s.next())),
            vfs_open: from_str!(c_ulong, expect!(s.next())),
            vfs_lookup: from_str!(c_ulong, expect!(s.next())),
            vfs_access: from_str!(c_ulong, expect!(s.next())),
            vfs_update_page: from_str!(c_ulong, expect!(s.next())),
            vfs_read_page: from_str!(c_ulong, expect!(s.next())),
            vfs_read_pages: from_str!(c_ulong, expect!(s.next())),
            vfs_write_page: from_str!(c_ulong, expect!(s.next())),
            vfs_write_pages: from_str!(c_ulong, expect!(s.next())),
            vfs_get_dents: from_str!(c_ulong, expect!(s.next())),
            vfs_set_attr: from_str!(c_ulong, expect!(s.next())),
            vfs_flush: from_str!(c_ulong, expect!(s.next())),
            vfs_fs_sync: from_str!(c_ulong, expect!(s.next())),
            vfs_lock: from_str!(c_ulong, expect!(s.next())),
            vfs_release: from_str!(c_ulong, expect!(s.next())),
            congestion_wait: from_str!(c_ulong, expect!(s.next())),
            set_attr_trunc: from_str!(c_ulong, expect!(s.next())),
            extend_write: from_str!(c_ulong, expect!(s.next())),
            silly_rename: from_str!(c_ulong, expect!(s.next())),
            short_read: from_str!(c_ulong, expect!(s.next())),
            short_write: from_str!(c_ulong, expect!(s.next())),
            delay: from_str!(c_ulong, expect!(s.next())),
            pnfs_read: from_str!(c_ulong, expect!(s.next())),
            pnfs_write: from_str!(c_ulong, expect!(s.next())),
        }
    }
}

/// Represents NFS data from `/proc/<pid>/mountstats` under the section `bytes`.
///
/// The underlying data structure in the kernel can be found under *fs/nfs/iostat.h* `nfs_iostat`.
/// The fields are documented in the kernel source only under *include/linux/nfs_iostat.h* `enum
/// nfs_stat_bytecounters`
#[derive(Debug, Copy, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct NFSByteCounter {
    pub normal_read: libc::c_ulonglong,
    pub normal_write: libc::c_ulonglong,
    pub direct_read: libc::c_ulonglong,
    pub direct_write: libc::c_ulonglong,
    pub server_read: libc::c_ulonglong,
    pub server_write: libc::c_ulonglong,
    pub pages_read: libc::c_ulonglong,
    pub pages_write: libc::c_ulonglong,
}

impl NFSByteCounter {
    fn from_str(s: &str) -> NFSByteCounter {
        use libc::c_ulonglong;
        let mut s = s.split_whitespace();
        NFSByteCounter {
            normal_read: from_str!(c_ulonglong, expect!(s.next())),
            normal_write: from_str!(c_ulonglong, expect!(s.next())),
            direct_read: from_str!(c_ulonglong, expect!(s.next())),
            direct_write: from_str!(c_ulonglong, expect!(s.next())),
            server_read: from_str!(c_ulonglong, expect!(s.next())),
            server_write: from_str!(c_ulonglong, expect!(s.next())),
            pages_read: from_str!(c_ulonglong, expect!(s.next())),
            pages_write: from_str!(c_ulonglong, expect!(s.next())),
        }
    }
}

/// Represents NFS data from `/proc/<pid>/mountstats` under the section of `per-op statistics`.
///
/// Here is what the Kernel says about the attributes:
///
/// Regarding `operations`, `transmissions` and `major_timeouts`:
///
/// >  These counters give an idea about how many request
/// >  transmissions are required, on average, to complete that
/// >  particular procedure.  Some procedures may require more
/// >  than one transmission because the server is unresponsive,
/// >  the client is retransmitting too aggressively, or the
/// >  requests are large and the network is congested.
///
/// Regarding `bytes_sent` and `bytes_recv`:
///
/// >  These count how many bytes are sent and received for a
/// >  given RPC procedure type.  This indicates how much load a
/// >  particular procedure is putting on the network.  These
/// >  counts include the RPC and ULP headers, and the request
/// >  payload.
///
/// Regarding `cum_queue_time`, `cum_resp_time` and `cum_total_req_time`:
///
/// >  The length of time an RPC request waits in queue before
/// >  transmission, the network + server latency of the request,
/// >  and the total time the request spent from init to release
/// >  are measured.
///
/// (source: *include/linux/sunrpc/metrics.h* `struct rpc_iostats`)
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct NFSOperationStat {
    /// Count of rpc operations.
    pub operations: libc::c_ulong,
    /// Count of rpc transmissions
    pub transmissions: libc::c_ulong,
    /// Count of rpc major timeouts
    pub major_timeouts: libc::c_ulong,
    /// Count of bytes send. Does not only include the RPC payload but the RPC headers as well.
    pub bytes_sent: libc::c_ulonglong,
    /// Count of bytes received as `bytes_sent`.
    pub bytes_recv: libc::c_ulonglong,
    /// How long all requests have spend in the queue before being send.
    pub cum_queue_time: Duration,
    /// How long it took to get a response back.
    pub cum_resp_time: Duration,
    /// How long all requests have taken from beeing queued to the point they where completely
    /// handled.
    pub cum_total_req_time: Duration,
}

impl NFSOperationStat {
    fn from_str(s: &str) -> NFSOperationStat {
        use libc::{c_ulong, c_ulonglong};
        let mut s = s.split_whitespace();

        let operations = from_str!(c_ulong, expect!(s.next()));
        let transmissions = from_str!(c_ulong, expect!(s.next()));
        let major_timeouts = from_str!(c_ulong, expect!(s.next()));
        let bytes_sent = from_str!(c_ulonglong, expect!(s.next()));
        let bytes_recv = from_str!(c_ulonglong, expect!(s.next()));
        let cum_queue_time_ms = from_str!(u64, expect!(s.next()));
        let cum_resp_time_ms = from_str!(u64, expect!(s.next()));
        let cum_total_req_time_ms = from_str!(u64, expect!(s.next()));

        NFSOperationStat {
            operations,
            transmissions,
            major_timeouts,
            bytes_sent,
            bytes_recv,
            cum_queue_time: Duration::from_millis(cum_queue_time_ms),
            cum_resp_time: Duration::from_millis(cum_resp_time_ms),
            cum_total_req_time: Duration::from_millis(cum_total_req_time_ms),
        }
    }
}

pub type NFSPerOpStats = HashMap<String, NFSOperationStat>;

#[derive(Debug, PartialEq)]
pub enum MMapPath {
    /// The file that is backing the mapping.
    Path(PathBuf),
    /// The process's heap.
    Heap,
    /// The initial process's (also known as the main thread's) stack.
    Stack,
    /// A thread's stack (where the `<tid>` is a thread ID).  It corresponds to the
    /// `/proc/<pid>/task/<tid>/` path.
    ///
    /// (since Linux 3.4)
    TStack(u32),
    /// The virtual dynamically linked shared object.
    Vdso,
    /// An anonymous mapping as obtained via mmap(2).
    Anonymous,
    /// Some other pseudo-path
    Other(String),
}

impl MMapPath {
    fn from(path: &str) -> MMapPath {
        match path.trim() {
            "" => MMapPath::Anonymous,
            "[heap]" => MMapPath::Heap,
            "[stack]" => MMapPath::Stack,
            "[vdso]" => MMapPath::Vdso,
            x if x.starts_with("[stack:") => {
                let mut s = x[1..x.len() - 1].split(':');
                let tid = from_str!(u32, s.nth(1).unwrap());
                MMapPath::TStack(tid)
            }
            x if x.starts_with('[') && x.ends_with(']') => {
                MMapPath::Other(x[1..x.len() - 1].to_string())
            }
            x => MMapPath::Path(PathBuf::from(x)),
        }
    }
}

/// Represents an entry in a `/proc/<pid>/maps` file.
///
/// To construct this structure, see [Process::maps()].
#[derive(Debug)]
pub struct MemoryMap {
    /// The address space in the process that the mapping occupies.
    pub address: (u64, u64),
    pub perms: String,
    /// The offset into the file/whatever
    pub offset: u64,
    /// The device (major, minor)
    pub dev: (i32, i32),
    /// The inode on that device
    ///
    /// 0 indicates that no inode is associated with the memory region, as would be the case with
    /// BSS (uninitialized data).
    pub inode: u32,
    pub pathname: MMapPath,
}

impl Io {
    pub fn from_reader<R: io::Read>(r: R) -> Option<Io> {
        use std::collections::HashMap;
        use std::io::{BufRead, BufReader};
        let mut map = HashMap::new();
        let reader = BufReader::new(r);

        for line in reader.lines() {
            let line = expect!(line, "Failed to read line");
            if line.is_empty() || !line.contains(' ') {
                continue;
            }
            let mut s = line.split_whitespace();
            let field = expect!(s.next(), "no field");
            let value = expect!(s.next(), "no value");

            let value = from_str!(u64, value);

            map.insert(field[..field.len() - 1].to_string(), value);
        }
        let io = Io {
            rchar: expect!(map.remove("rchar")),
            wchar: expect!(map.remove("wchar")),
            syscr: expect!(map.remove("syscr")),
            syscw: expect!(map.remove("syscw")),
            read_bytes: expect!(map.remove("read_bytes")),
            write_bytes: expect!(map.remove("write_bytes")),
            cancelled_write_bytes: expect!(map.remove("cancelled_write_bytes")),
        };

        if !map.is_empty() {
            if cfg!(test) {
                panic!("io map is not empty: {:#?}", map);
            }
        }

        Some(io)
    }
}

#[derive(Debug)]
pub enum FDTarget {
    /// A file or device
    Path(PathBuf),
    /// A socket type, with an inode
    Socket(u32),
    Net(u32),
    Pipe(u32),
    /// A file descriptor that have no corresponding inode.
    AnonInode(String),
    /// A memfd file descriptor with a name.
    MemFD(String),
    /// Some other file descriptor type, with an inode.
    Other(String, u32),
}

impl FromStr for FDTarget {
    type Err = String;
    fn from_str(s: &str) -> Result<FDTarget, String> {
        if !s.starts_with('/') && s.contains(':') {
            let mut s = s.split(':');
            let fd_type = s.next().unwrap();
            match fd_type {
                "socket" => {
                    let inode = expect!(s.next(), "socket inode");
                    let inode = u32::from_str_radix(&inode[1..inode.len() - 1], 10).unwrap();
                    Ok(FDTarget::Socket(inode))
                }
                "net" => {
                    let inode = expect!(s.next(), "net inode");
                    let inode = u32::from_str_radix(&inode[1..inode.len() - 1], 10).unwrap();
                    Ok(FDTarget::Net(inode))
                }
                "pipe" => {
                    let inode = expect!(s.next(), "pipe inode");
                    let inode = u32::from_str_radix(&inode[1..inode.len() - 1], 10).unwrap();
                    Ok(FDTarget::Pipe(inode))
                }
                "anon_inode" => Ok(FDTarget::AnonInode(
                    expect!(s.next(), "anon inode").to_string(),
                )),
                "/memfd" => Ok(FDTarget::MemFD(expect!(s.next(), "memfd name").to_string())),
                x => {
                    let inode = expect!(s.next(), "other inode");
                    let inode = u32::from_str_radix(&inode[1..inode.len() - 1], 10).unwrap();
                    Ok(FDTarget::Other(x.to_string(), inode))
                }
            }
        } else {
            Ok(FDTarget::Path(PathBuf::from(s)))
        }
    }
}

#[derive(Debug)]
pub struct FDInfo {
    pub fd: u32,
    pub target: FDTarget,
}

macro_rules! since_kernel {
    ($a:tt, $b:tt, $c:tt, $e:expr) => {
        if *KERNEL >= KernelVersion::new($a, $b, $c) {
            Some($e)
        } else {
            None
        }
    };
}

impl Stat {
    pub fn from_reader<R: io::Read>(mut r: R) -> Option<Stat> {
        // read in entire thing, this is only going to be 1 line
        let mut buf = String::new();
        r.read_to_string(&mut buf).ok()?;
        let buf = buf.trim();

        // find the first opening paren, and split off the first part (pid)
        let start_paren = buf.find('(')?;
        let end_paren = buf.rfind(')')?;
        let pid_s = &buf[..start_paren - 1];
        let comm = buf[start_paren + 1..end_paren].to_string();
        let rest = &buf[end_paren + 2..];

        let pid = FromStr::from_str(pid_s).unwrap();

        let mut rest = rest.split(' ');
        let state = rest.next().unwrap().chars().next().unwrap();

        let ppid = from_iter(&mut rest);
        let pgrp = from_iter(&mut rest);
        let session = from_iter(&mut rest);
        let tty_nr = from_iter(&mut rest);
        let tpgid = from_iter(&mut rest);
        let flags = from_iter(&mut rest);
        let minflt = from_iter(&mut rest);
        let cminflt = from_iter(&mut rest);
        let majflt = from_iter(&mut rest);
        let cmajflt = from_iter(&mut rest);
        let utime = from_iter(&mut rest);
        let stime = from_iter(&mut rest);
        let cutime = from_iter(&mut rest);
        let cstime = from_iter(&mut rest);
        let priority = from_iter(&mut rest);
        let nice = from_iter(&mut rest);
        let num_threads = from_iter(&mut rest);
        let itrealvalue = from_iter(&mut rest);
        let starttime = from_iter(&mut rest);
        let vsize = from_iter(&mut rest);
        let rss = from_iter(&mut rest);
        let rsslim = from_iter(&mut rest);
        let startcode = from_iter(&mut rest);
        let endcode = from_iter(&mut rest);
        let startstack = from_iter(&mut rest);
        let kstkesp = from_iter(&mut rest);
        let kstkeip = from_iter(&mut rest);
        let signal = from_iter(&mut rest);
        let blocked = from_iter(&mut rest);
        let sigignore = from_iter(&mut rest);
        let sigcatch = from_iter(&mut rest);
        let wchan = from_iter(&mut rest);
        let nswap = from_iter(&mut rest);
        let cnswap = from_iter(&mut rest);

        let exit_signal = since_kernel!(2, 1, 22, from_iter(&mut rest));
        let processor = since_kernel!(2, 2, 8, from_iter(&mut rest));
        let rt_priority = since_kernel!(2, 5, 19, from_iter(&mut rest));
        let policy = since_kernel!(2, 5, 19, from_iter(&mut rest));
        let delayacct_blkio_ticks = since_kernel!(2, 6, 18, from_iter(&mut rest));
        let guest_time = since_kernel!(2, 6, 24, from_iter(&mut rest));
        let cguest_time = since_kernel!(2, 6, 24, from_iter(&mut rest));
        let start_data = since_kernel!(3, 3, 0, from_iter(&mut rest));
        let end_data = since_kernel!(3, 3, 0, from_iter(&mut rest));
        let start_brk = since_kernel!(3, 3, 0, from_iter(&mut rest));
        let arg_start = since_kernel!(3, 5, 0, from_iter(&mut rest));
        let arg_end = since_kernel!(3, 5, 0, from_iter(&mut rest));
        let env_start = since_kernel!(3, 5, 0, from_iter(&mut rest));
        let env_end = since_kernel!(3, 5, 0, from_iter(&mut rest));
        let exit_code = since_kernel!(3, 5, 0, from_iter(&mut rest));

        Some(Stat {
            pid,
            comm,
            state,
            ppid,
            pgrp,
            session,
            tty_nr,
            tpgid,
            flags,
            minflt,
            cminflt,
            majflt,
            cmajflt,
            utime,
            stime,
            cutime,
            cstime,
            priority,
            nice,
            num_threads,
            itrealvalue,
            starttime,
            vsize,
            rss,
            rsslim,
            startcode,
            endcode,
            startstack,
            kstkesp,
            kstkeip,
            signal,
            blocked,
            sigignore,
            sigcatch,
            wchan,
            nswap,
            cnswap,
            exit_signal,
            processor,
            rt_priority,
            policy,
            delayacct_blkio_ticks,
            guest_time,
            cguest_time,
            start_data,
            end_data,
            start_brk,
            arg_start,
            arg_end,
            env_start,
            env_end,
            exit_code,
        })
    }

    pub fn state(&self) -> ProcState {
        ProcState::from_char(self.state).unwrap()
    }

    pub fn tty_nr(&self) -> (i32, i32) {
        // minor is bits 31-20 and 7-0
        // major is 15-8

        // mmmmmmmmmmmm____MMMMMMMMmmmmmmmm
        // 11111111111100000000000000000000
        let major = (self.tty_nr & 0xfff00) >> 8;
        let minor = (self.tty_nr & 0x000ff) | ((self.tty_nr >> 12) & 0xfff00);
        (major, minor)
    }

    pub fn flags(&self) -> StatFlags {
        StatFlags::from_bits(self.flags).unwrap_or_else(|| {
            panic!(format!(
                "Can't construct flags bitfield from {:?}",
                self.flags
            ))
        })
    }

    pub fn starttime(&self) -> DateTime<Local> {
        let seconds_since_boot = self.starttime as f32 / *TICKS_PER_SECOND as f32;

        *BOOTTIME + chrono::Duration::milliseconds((seconds_since_boot * 1000.0) as i64)
    }

    /// Gets the Resident Set Size (in bytes)
    ///
    /// The `rss` field will return the same value in pages
    pub fn rss_bytes(&self) -> i64 {
        self.rss * *PAGESIZE
    }
}

/// Represents a process in `/proc/<pid>`.
///
/// The `stat` structure is pre-populated because it's useful info, but other data is loaded on
/// demand (and so might fail, if the process no longer exist).
#[derive(Debug, Clone)]
pub struct Process {
    /// Process status, based on the `/proc/<pid>/stat` file.
    pub stat: Stat,
    /// The user id of the owner of this process
    pub owner: u32,
    pub(crate) root: PathBuf,
}

impl Process {
    /// Tries to create a `Process` based on a PID.
    ///
    /// This can fail if the process doesn't exist, or if you don't have permission to access it.
    pub fn new(pid: pid_t) -> ProcResult<Process> {
        let root = PathBuf::from("/proc").join(format!("{}", pid));
        let stat = Stat::from_reader(File::open(root.join("stat"))?).unwrap();

        let md = std::fs::metadata(&root)?;

        Ok(Process {
            root,
            stat,
            owner: md.st_uid(),
        })
    }

    /// Returns a `Process` for the currently running process.
    ///
    /// This is done by using the `/proc/self` symlink
    pub fn myself() -> ProcResult<Process> {
        let root = PathBuf::from("/proc/self");
        let stat = Stat::from_reader(File::open(root.join("stat"))?).unwrap();
        let md = std::fs::metadata(&root)?;

        Ok(Process {
            root,
            stat,
            owner: md.st_uid(),
        })
    }

    /// Returns the complete command line for the process, unless the process is a zombie.
    ///
    ///
    pub fn cmdline(&self) -> ProcResult<Vec<String>> {
        let mut buf = String::new();
        let mut f = File::open(self.root.join("cmdline"))?;
        f.read_to_string(&mut buf)?;
        Ok(buf
            .split('\0')
            .filter_map(|s| {
                if !s.is_empty() {
                    Some(s.to_string())
                } else {
                    None
                }
            })
            .collect())
    }

    /// Returns the process ID for this process.
    pub fn pid(&self) -> pid_t {
        self.stat.pid
    }

    /// Is this process still alive?
    pub fn is_alive(&self) -> bool {
        match Process::new(self.pid()) {
            Ok(prc) => {
                // assume that the command line, uid and starttime don't change during a processes lifetime
                // additionally, do not consider defunct processes as "alive"
                // i.e. if they are different, a new process has the same PID as `self` and so `self` is not considered alive
                prc.stat.comm == self.stat.comm
                    && prc.owner == self.owner
                    && prc.stat.starttime == self.stat.starttime
                    && prc.stat.state() != ProcState::Zombie
                    && self.stat.state() != ProcState::Zombie
            }
            _ => false,
        }
    }

    /// The the current working directory of the process.  This done by dereferencing the
    /// `/proc/pid/cwd` symbolic link.
    ///
    /// In a multithreaded process, the contents of this symbolic link are not available if the
    /// main thread has already terminated (typically by calling pthread_exit(3)).
    ///
    /// Permission  to  dereference or read (readlink(2)) this symbolic link is governed by a
    /// ptrace access mode PTRACE_MODE_READ_FSCREDS check;
    pub fn cwd(&self) -> ProcResult<PathBuf> {
        Ok(std::fs::read_link(self.root.join("cwd"))?)
    }

    /// Gets the current environment for the process.  This is done by reading the
    /// `/proc/pid/environ` file.
    pub fn environ(&self) -> ProcResult<HashMap<OsString, OsString>> {
        use std::ffi::OsStr;
        use std::fs::File;
        use std::os::unix::ffi::OsStrExt;

        let mut map = HashMap::new();

        let mut file = File::open(self.root.join("environ"))?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        for slice in buf.split(|b| *b == 0) {
            // slice will be in the form key=var, so split on the first equals sign
            let mut split = slice.splitn(2, |b| *b == b'=');
            if let (Some(k), Some(v)) = (split.next(), split.next()) {
                map.insert(
                    OsStr::from_bytes(k).to_os_string(),
                    OsStr::from_bytes(v).to_os_string(),
                );
            };
            //let env = OsStr::from_bytes(slice);
        }

        Ok(map)
    }

    /// The actual path of the executed command, taken by resolving the `/proc/pid/exe` symbolic
    /// link.
    ///
    /// Under Linux 2.2 and later, this symbolic link contains the actual pathname of
    /// the executed command.  If the pathname has been unlinked, the symbolic link will  contain
    /// the  string  '(deleted)' appended  to the original pathname.  In a multithreaded process,
    /// the contents of this symbolic link are not available if the main thread has already
    /// terminated (typically by calling pthread_exit(3)).
    pub fn exe(&self) -> ProcResult<PathBuf> {
        Ok(std::fs::read_link(self.root.join("exe"))?)
    }

    /// Return the Io stats for this process, based on the `/proc/pid/io` file.
    ///
    /// (since kernel 2.6.20)
    pub fn io(&self) -> ProcResult<Io> {
        let file = File::open(self.root.join("io"))?;
        Ok(Io::from_reader(file).unwrap())
    }

    /// Return a list of the currently mapped memory regions and their access permissions, based on
    /// the `/proc/pid/maps` file.
    pub fn maps(&self) -> ProcResult<Vec<MemoryMap>> {
        use std::io::{BufRead, BufReader};

        let file = File::open(self.root.join("maps"))?;

        let reader = BufReader::new(file);

        Ok(reader
            .lines()
            .map(|line| {
                let line = line.unwrap();
                let mut s = line.splitn(6, ' ');
                let address = expect!(s.next(), "maps::address");
                let perms = expect!(s.next(), "maps::perms");
                let offset = expect!(s.next(), "maps::offset");
                let dev = expect!(s.next(), "maps::dev");
                let inode = expect!(s.next(), "maps::inode");
                let path = expect!(s.next(), "maps::path");

                MemoryMap {
                    address: split_into_num(address, '-', 16),
                    perms: perms.to_string(),
                    offset: from_str!(u64, offset, 16),
                    dev: split_into_num(dev, ':', 16),
                    inode: from_str!(u32, inode),
                    pathname: MMapPath::from(path),
                }
            })
            .collect())
    }

    /// Gets a list of open file descriptors for a process
    pub fn fd(&self) -> ProcResult<Vec<FDInfo>> {
        use std::ffi::OsStr;
        use std::fs::read_link;

        let mut vec = Vec::new();

        for dir in self.root.join("fd").read_dir()? {
            let entry = dir?;
            let fd = u32::from_str_radix(entry.file_name().to_str().unwrap(), 10).unwrap();
            //  note: the link might have disappeared between the time we got the directory listing
            //  and now.  So if the read_link fails, that's OK
            if let Ok(link) = read_link(entry.path()) {
                let link_os: &OsStr = link.as_ref();
                vec.push(FDInfo {
                    fd,
                    target: FDTarget::from_str(link_os.to_str().unwrap()).unwrap(),
                });
            }
        }
        Ok(vec)
    }

    /// Lists which memory segments are written to the core dump in the event that a core dump is performed.
    ///
    /// By default, the following bits are set:
    /// 0, 1, 4 (if the CONFIG_CORE_DUMP_DEFAULT_ELF_HEADERS kernel configuration option is enabled), and 5.
    /// This default can be modified at boot time using the core dump_filter boot option.
    ///
    /// This function will return `Err(ProcError::NotFound)` if the `coredump_filter` file can't be
    /// found.  If it returns `Ok(None)` then the process has no coredump_filter
    pub fn coredump_filter(&self) -> ProcResult<Option<CoredumpFlags>> {
        use std::fs::File;
        let mut file = File::open(self.root.join("coredump_filter"))?;
        let mut s = String::new();
        file.read_to_string(&mut s)?;
        if s.trim().is_empty() {
            return Ok(None);
        }
        let flags = from_str!(u32, &s.trim(), 16, pid:self.stat.pid);

        Ok(Some(expect!(CoredumpFlags::from_bits(flags))))
    }

    /// Gets the process's autogroup membership
    ///
    /// (since Linux 2.6.38 and requires CONFIG_SCHED_AUTOGROUP)
    pub fn autogroup(&self) -> ProcResult<String> {
        let mut s = String::new();
        let mut file = File::open(self.root.join("autogroup"))?;
        file.read_to_string(&mut s)?;
        Ok(s)
    }

    /// Get the process's auxiliary vector
    ///
    /// (since 2.6.0-test7)
    pub fn auxv(&self) -> ProcResult<HashMap<u32, u32>> {
        use byteorder::{NativeEndian, ReadBytesExt};

        let mut file = File::open(self.root.join("auxv"))?;
        let mut map = HashMap::new();

        loop {
            let key = file.read_u32::<NativeEndian>()?;
            let value = file.read_u32::<NativeEndian>()?;
            if key == 0 && value == 0 {
                break;
            }
            map.insert(key, value);
        }

        Ok(map)
    }

    /// Returns the [MountStat] data for this processes mount namespace.
    pub fn mountstats(&self) -> ProcResult<Vec<MountStat>> {
        let file = File::open(self.root.join("mountstats"))?;
        Ok(MountStat::from_reader(file))
    }

    /// Gets the symbolic name corresponding to the location in the kernel where the process is sleeping.
    ///
    /// (since Linux 2.6.0)
    pub fn wchan(&self) -> ProcResult<String> {
        let mut s = String::new();
        let mut file = File::open(self.root.join("wchan"))?;
        file.read_to_string(&mut s)?;
        Ok(s)
    }
}

pub fn all_processes() -> Vec<Process> {
    let mut v = Vec::new();
    for dir in expect!(std::fs::read_dir("/proc/"), "No /proc/ directory") {
        if let Ok(entry) = dir {
            if let Ok(pid) = i32::from_str(&entry.file_name().to_string_lossy()) {
                if let Ok(prc) = Process::new(pid) {
                    v.push(prc);
                }
            }
        }
    }

    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_unwrap<T>(val: ProcResult<T>) {
        match val {
            Ok(t) => {}
            Err(ProcError::PermissionDenied) if unsafe { libc::geteuid() } != 0 => {
                // we are not root, and so a permission denied error is OK
            }
            Err(ProcError::NotFound) => {}
            Err(err) => panic!("{:?}", err),
        }
    }

    #[test]
    fn test_self_proc() {
        let myself = Process::myself().unwrap();
        println!("{:#?}", myself);
        println!("state: {:?}", myself.stat.state());
        println!("tty: {:?}", myself.stat.tty_nr());
        println!("flags: {:?}", myself.stat.flags());
        println!("starttime: {:#?}", myself.stat.starttime());

        let kernel = KernelVersion::current().unwrap();

        if kernel >= KernelVersion::new(2, 1, 22) {
            assert!(myself.stat.exit_signal.is_some());
        } else {
            assert!(myself.stat.exit_signal.is_none());
        }

        if kernel >= KernelVersion::new(2, 2, 8) {
            assert!(myself.stat.processor.is_some());
        } else {
            assert!(myself.stat.processor.is_none());
        }

        if kernel >= KernelVersion::new(2, 5, 19) {
            assert!(myself.stat.rt_priority.is_some());
        } else {
            assert!(myself.stat.rt_priority.is_none());
        }

        if kernel >= KernelVersion::new(2, 5, 19) {
            assert!(myself.stat.rt_priority.is_some());
            assert!(myself.stat.policy.is_some());
        } else {
            assert!(myself.stat.rt_priority.is_none());
            assert!(myself.stat.policy.is_none());
        }

        if kernel >= KernelVersion::new(2, 6, 18) {
            assert!(myself.stat.delayacct_blkio_ticks.is_some());
        } else {
            assert!(myself.stat.delayacct_blkio_ticks.is_none());
        }

        if kernel >= KernelVersion::new(2, 6, 24) {
            assert!(myself.stat.guest_time.is_some());
            assert!(myself.stat.cguest_time.is_some());
        } else {
            assert!(myself.stat.guest_time.is_none());
            assert!(myself.stat.cguest_time.is_none());
        }

        if kernel >= KernelVersion::new(3, 3, 0) {
            assert!(myself.stat.start_data.is_some());
            assert!(myself.stat.end_data.is_some());
            assert!(myself.stat.start_brk.is_some());
        } else {
            assert!(myself.stat.start_data.is_none());
            assert!(myself.stat.end_data.is_none());
            assert!(myself.stat.start_brk.is_none());
        }

        if kernel >= KernelVersion::new(3, 5, 0) {
            assert!(myself.stat.arg_start.is_some());
            assert!(myself.stat.arg_end.is_some());
            assert!(myself.stat.env_start.is_some());
            assert!(myself.stat.env_end.is_some());
            assert!(myself.stat.exit_code.is_some());
        } else {
            assert!(myself.stat.arg_start.is_none());
            assert!(myself.stat.arg_end.is_none());
            assert!(myself.stat.env_start.is_none());
            assert!(myself.stat.env_end.is_none());
            assert!(myself.stat.exit_code.is_none());
        }
    }

    #[test]
    fn test_all() {
        for prc in all_processes() {
            // note: this test doesn't unwrap, since some of this data requires root to access
            // so permission denied errors are common
            // TODO unwrap but allow for permission denied errors in this test

            prc.stat.flags();
            prc.stat.starttime();
            check_unwrap(prc.cmdline());
            check_unwrap(prc.environ());
            check_unwrap(prc.fd());
            check_unwrap(prc.io());
            check_unwrap(prc.maps());
            check_unwrap(prc.coredump_filter());
            check_unwrap(prc.autogroup());
            check_unwrap(prc.auxv());
            check_unwrap(prc.cgroups());
        }
    }

    #[test]
    fn test_proc_alive() {
        let myself = Process::myself().unwrap();
        assert!(myself.is_alive());
    }

    #[test]
    fn test_proc_environ() {
        let myself = Process::myself().unwrap();
        let proc_environ = myself.environ().unwrap();

        let std_environ: HashMap<_, _> = std::env::vars_os().collect();
        assert_eq!(proc_environ, std_environ);
    }

    #[test]
    fn test_error_handling() {
        // getting the proc struct should be OK
        let init = Process::new(1).unwrap();

        // but accessing data should result in an error (unless we are running as root!)
        assert!(!init.cwd().is_ok());
        assert!(!init.environ().is_ok());
    }

    #[test]
    fn test_proc_exe() {
        let myself = Process::myself().unwrap();
        let proc_exe = myself.exe().unwrap();
        let std_exe = std::env::current_exe().unwrap();
        assert_eq!(proc_exe, std_exe);
    }

    #[test]
    fn test_proc_io() {
        let myself = Process::myself().unwrap();
        let kernel = KernelVersion::current().unwrap();
        let io = myself.io();
        println!("{:?}", io);
        if let Ok(_) = io {
            assert!(kernel >= KernelVersion::new(2, 6, 20));
        }
    }

    #[test]
    fn test_proc_maps() {
        let myself = Process::myself().unwrap();
        let maps = myself.maps().unwrap();
        for map in maps {
            println!("{:?}", map);
        }
    }

    #[test]
    fn test_mmap_path() {
        assert_eq!(MMapPath::from("[stack]"), MMapPath::Stack);
        assert_eq!(MMapPath::from("[foo]"), MMapPath::Other("foo".to_owned()));
        assert_eq!(MMapPath::from(""), MMapPath::Anonymous);
        assert_eq!(MMapPath::from("[stack:154]"), MMapPath::TStack(154));
        assert_eq!(
            MMapPath::from("/lib/libfoo.so"),
            MMapPath::Path(PathBuf::from("/lib/libfoo.so"))
        );
    }
    #[test]
    fn test_proc_fd() {
        let myself = Process::myself().unwrap();
        for fd in myself.fd().unwrap() {
            println!("{:?}", fd);
        }
    }

    #[test]
    fn test_proc_coredump() {
        let myself = Process::myself().unwrap();
        let flags = myself.coredump_filter();
        println!("{:?}", flags);
    }

    #[test]
    fn test_proc_auxv() {
        let myself = Process::myself().unwrap();
        let auxv = myself.auxv().unwrap();
        println!("{:?}", auxv);
    }

    #[test]
    fn test_proc_mountstats() {
        let simple = MountStat::from_reader(
            "device /dev/md127 mounted on /boot with fstype ext2 
device /dev/md124 mounted on /home with fstype ext4 
device tmpfs mounted on /run/user/0 with fstype tmpfs 
"
            .as_bytes(),
        );
        let simple_parsed = vec![
            MountStat {
                device: Some("/dev/md127".to_string()),
                mount_point: PathBuf::from("/boot"),
                fs: "ext2".to_string(),
                statistics: None,
            },
            MountStat {
                device: Some("/dev/md124".to_string()),
                mount_point: PathBuf::from("/home"),
                fs: "ext4".to_string(),
                statistics: None,
            },
            MountStat {
                device: Some("tmpfs".to_string()),
                mount_point: PathBuf::from("/run/user/0"),
                fs: "tmpfs".to_string(),
                statistics: None,
            },
        ];
        assert_eq!(simple, simple_parsed);
        let mountstats = MountStat::from_reader("device elwe:/space mounted on /srv/elwe/space with fstype nfs4 statvers=1.1 
       opts:   rw,vers=4.1,rsize=131072,wsize=131072,namlen=255,acregmin=3,acregmax=60,acdirmin=30,acdirmax=60,hard,proto=tcp,port=0,timeo=600,retrans=2,sec=krb5,clientaddr=10.0.1.77,local_lock=none 
       age:    3542 
       impl_id:        name='',domain='',date='0,0' 
       caps:   caps=0x3ffdf,wtmult=512,dtsize=32768,bsize=0,namlen=255 
       nfsv4:  bm0=0xfdffbfff,bm1=0x40f9be3e,bm2=0x803,acl=0x3,sessions,pnfs=not configured 
       sec:    flavor=6,pseudoflavor=390003 
       events: 114 1579 5 3 132 20 3019 1 2 3 4 5 115 1 4 1 2 4 3 4 5 6 7 8 9 0 1  
       bytes:  1 2 3 4 5 6 7 8  
       RPC iostats version: 1.0  p/v: 100003/4 (nfs) 
       xprt:   tcp 909 0 1 0 2 294 294 0 294 0 2 0 0 
       per-op statistics 
               NULL: 0 0 0 0 0 0 0 0 
               READ: 1 2 3 4 5 6 7 8 
              WRITE: 0 0 0 0 0 0 0 0 
             COMMIT: 0 0 0 0 0 0 0 0 
               OPEN: 1 1 0 320 420 0 124 124 
        ".as_bytes());
        let nfs_v4 = &mountstats[0];
        match &nfs_v4.statistics {
            Some(stats) => {
                assert_eq!(
                    "1.1".to_string(),
                    stats.version,
                    "mountstats version wrongly parsed."
                );
                assert_eq!(Duration::from_secs(3542), stats.age);
                assert_eq!(1, stats.bytes.normal_read);
                assert_eq!(114, stats.events.inode_revalidate);
                assert!(stats.server_caps().is_some());
            }
            None => {
                assert!(false, "Failed to retrieve nfs statistics");
            }
        }
    }
    #[test]
    fn test_proc_mountstats_live() {
        // this tries to parse a live mountstats file
        // thera are no assertions, but we still want to check for parsing errors (which can
        // cause panics)

        let stats = MountStat::from_reader(File::open("/proc/self/mountstats").unwrap());
        for stat in stats {
            println!("{:#?}", stat);
            if let Some(nfs) = stat.statistics {
                println!("  {:?}", nfs.server_caps().unwrap());
            }
        }
    }

    #[test]
    fn test_proc_wchan() {
        let myself = Process::myself().unwrap();
        let wchan = myself.wchan().unwrap();
        println!("{:?}", wchan);
    }

}
