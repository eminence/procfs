use super::*;

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
#[cfg(unix)]
use std::os::linux::fs::MetadataExt;
use std::path::PathBuf;
use std::str::FromStr;

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

//impl<'a, 'b, T> ProcFrom<&'b mut T> for u32 where T: Iterator<Item=&'a str> + Sized, 'a: 'b {
//    fn from(i: &'b mut T) -> u32 {
//        let s = i.next().unwrap();
//        u32::from_str_radix(s, 10).unwrap()
//    }
//}

impl<'a, I, U> ProcFrom<I> for U
where
    I: IntoIterator<Item = &'a str>,
    U: FromStr,
{
    fn from(i: I) -> U {
        let mut iter = i.into_iter();
        let val = iter.next().expect("Missing iterator next item");
        match FromStr::from_str(val) {
            Ok(u) => u,
            Err(..) => panic!("Failed to convert".to_string()),
        }
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
        ProcState::from_char(s.chars().next().expect("empty string")).ok_or("Failed to convert")
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
    /// not provide information on real-time signals; use /proc/<pid>/status instead.
    pub signal: u64,
    /// The bitmap of blocked signals, displayed as a decimal number.  Obsolete, because it does
    /// not provide information on  real-time signals; use /proc/<pid>/status instead.
    pub blocked: u64,
    /// The  bitmap of ignored signals, displayed as a decimal number.  Obsolete, because it does
    /// not provide information on real-time signals; use /proc/<pid>/status instead.
    pub sigignore: u64,
    /// The bitmap of caught signals, displayed as a decimal number.  Obsolete, because it does not
    /// provide information  on  real-time signals; use /proc/<pid>/status instead.
    pub sigcatch: u64,
    /// This  is  the  "channel"  in which the process is waiting.  It is the address of a location
    /// in the kernel where the process is sleeping.  The corresponding symbolic name can be found in
    /// /proc/<pid>/wchan.
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

#[derive(Debug, PartialEq)]
pub enum MMapPath {
    /// The file that is backing the mapping.
    Path(PathBuf),
    /// The process's heap.
    Heap,
    /// The initial process's (also known as the main thread's) stack.
    Stack,
    /// A thread's stack (where the <tid> is a thread ID).  It corresponds to the
    /// /proc/<pid>/task/<tid>/ path.
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
                let tid = u32::from_str_radix(s.nth(1).unwrap(), 10).unwrap();
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
            let line = line.expect("Failed to read line");
            if line.is_empty() {
                continue;
            }
            let mut s = line.split_whitespace();
            let field = s.next().expect("no field");
            let value = s.next().expect("no value");

            let value = u64::from_str_radix(value, 10).expect("Failed to parse number");

            map.insert(field[..field.len() - 1].to_string(), value);
        }
        let io = Io {
            rchar: map.remove("rchar").expect("rchar"),
            wchar: map.remove("wchar").expect("wchar"),
            syscr: map.remove("syscr").expect("syscr"),
            syscw: map.remove("syscw").expect("syscw"),
            read_bytes: map.remove("read_bytes").expect("read_bytes"),
            write_bytes: map.remove("write_bytes").expect("write_bytes"),
            cancelled_write_bytes: map
                .remove("cancelled_write_bytes")
                .expect("cancelled_write_bytes"),
        };

        if !map.is_empty() {
            panic!("meminfo map is not empty: {:#?}", map);
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
        if s.contains(':') {
            let mut s = s.split(':');
            let fd_type = s.next().unwrap();
            match fd_type {
                "socket" => {
                    let inode = s.next().expect("socket inode");
                    let inode = u32::from_str_radix(&inode[1..inode.len() - 1], 10).unwrap();
                    Ok(FDTarget::Socket(inode))
                }
                "net" => {
                    let inode = s.next().expect("net inode");
                    let inode = u32::from_str_radix(&inode[1..inode.len() - 1], 10).unwrap();
                    Ok(FDTarget::Net(inode))
                }
                "pipe" => {
                    let inode = s.next().expect("pipe inode");
                    let inode = u32::from_str_radix(&inode[1..inode.len() - 1], 10).unwrap();
                    Ok(FDTarget::Pipe(inode))
                }
                "anon_inode" => {
                    Ok(FDTarget::AnonInode(s.next().expect("anon inode").to_string()))
                }
                "/memfd" => {
                    Ok(FDTarget::MemFD(s.next().expect("memfd name").to_string()))
                }
                x => {
                    let inode = s.next().expect("other inode");
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

        let ppid = ProcFrom::from(&mut rest);
        let pgrp = ProcFrom::from(&mut rest);
        let session = ProcFrom::from(&mut rest);
        let tty_nr = ProcFrom::from(&mut rest);
        let tpgid = ProcFrom::from(&mut rest);
        let flags = ProcFrom::from(&mut rest);
        let minflt = ProcFrom::from(&mut rest);
        let cminflt = ProcFrom::from(&mut rest);
        let majflt = ProcFrom::from(&mut rest);
        let cmajflt = ProcFrom::from(&mut rest);
        let utime = ProcFrom::from(&mut rest);
        let stime = ProcFrom::from(&mut rest);
        let cutime = ProcFrom::from(&mut rest);
        let cstime = ProcFrom::from(&mut rest);
        let priority = ProcFrom::from(&mut rest);
        let nice = ProcFrom::from(&mut rest);
        let num_threads = ProcFrom::from(&mut rest);
        let itrealvalue = ProcFrom::from(&mut rest);
        let starttime = ProcFrom::from(&mut rest);
        let vsize = ProcFrom::from(&mut rest);
        let rss = ProcFrom::from(&mut rest);
        let rsslim = ProcFrom::from(&mut rest);
        let startcode = ProcFrom::from(&mut rest);
        let endcode = ProcFrom::from(&mut rest);
        let startstack = ProcFrom::from(&mut rest);
        let kstkesp = ProcFrom::from(&mut rest);
        let kstkeip = ProcFrom::from(&mut rest);
        let signal = ProcFrom::from(&mut rest);
        let blocked = ProcFrom::from(&mut rest);
        let sigignore = ProcFrom::from(&mut rest);
        let sigcatch = ProcFrom::from(&mut rest);
        let wchan = ProcFrom::from(&mut rest);
        let nswap = ProcFrom::from(&mut rest);
        let cnswap = ProcFrom::from(&mut rest);

        let exit_signal = since_kernel!(2, 1, 22, ProcFrom::from(&mut rest));
        let processor = since_kernel!(2, 2, 8, ProcFrom::from(&mut rest));
        let rt_priority = since_kernel!(2, 5, 19, ProcFrom::from(&mut rest));
        let policy = since_kernel!(2, 5, 19, ProcFrom::from(&mut rest));
        let delayacct_blkio_ticks = since_kernel!(2, 6, 18, ProcFrom::from(&mut rest));
        let guest_time = since_kernel!(2, 6, 24, ProcFrom::from(&mut rest));
        let cguest_time = since_kernel!(2, 6, 24, ProcFrom::from(&mut rest));
        let start_data = since_kernel!(3, 3, 0, ProcFrom::from(&mut rest));
        let end_data = since_kernel!(3, 3, 0, ProcFrom::from(&mut rest));
        let start_brk = since_kernel!(3, 3, 0, ProcFrom::from(&mut rest));
        let arg_start = since_kernel!(3, 5, 0, ProcFrom::from(&mut rest));
        let arg_end = since_kernel!(3, 5, 0, ProcFrom::from(&mut rest));
        let env_start = since_kernel!(3, 5, 0, ProcFrom::from(&mut rest));
        let env_end = since_kernel!(3, 5, 0, ProcFrom::from(&mut rest));
        let exit_code = since_kernel!(3, 5, 0, ProcFrom::from(&mut rest));

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
        let stat = Stat::from_reader(proctry!(File::open(root.join("stat")))).unwrap();

        let md = proctry!(std::fs::metadata(&root));

        ProcResult::Ok(Process {
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
        let stat = Stat::from_reader(proctry!(File::open(root.join("stat")))).unwrap();
        let md = proctry!(std::fs::metadata(&root));

        ProcResult::Ok(Process {
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
        let mut f = proctry!(File::open(self.root.join("cmdline")));
        proctry!(f.read_to_string(&mut buf));
        ProcResult::Ok(
            buf.split('\0')
                .filter_map(|s| {
                    if !s.is_empty() {
                        Some(s.to_string())
                    } else {
                        None
                    }
                })
                .collect(),
        )
    }

    /// Returns the process ID for this process.
    pub fn pid(&self) -> pid_t {
        self.stat.pid
    }

    /// Is this process still alive?
    pub fn is_alive(&self) -> bool {
        match Process::new(self.pid()) {
            ProcResult::Ok(prc) => {
                // assume that the command line and uid don't change during a processes lifetime
                // i.e. if they are different, a new process has the same PID as `self` and so `self` is not considered alive
                prc.stat.comm == self.stat.comm && prc.owner == self.owner
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
        ProcResult::Ok(proctry!(std::fs::read_link(self.root.join("cwd"))))
    }

    /// Gets the current environment for the process.  This is done by reading the
    /// `/proc/pid/environ` file.
    pub fn environ(&self) -> ProcResult<HashMap<OsString, OsString>> {
        use std::ffi::OsStr;
        use std::fs::File;
        use std::os::unix::ffi::OsStrExt;

        let mut map = HashMap::new();

        let mut file = proctry!(File::open(self.root.join("environ")));
        let mut buf = Vec::new();
        proctry!(file.read_to_end(&mut buf));

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

        ProcResult::Ok(map)
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
        ProcResult::Ok(proctry!(std::fs::read_link(self.root.join("exe"))))
    }

    /// Return the Io stats for this process, based on the `/proc/pid/io` file.
    ///
    /// (since kernel 2.6.20)
    pub fn io(&self) -> ProcResult<Io> {
        let file = proctry!(File::open(self.root.join("io")));
        ProcResult::Ok(Io::from_reader(file).unwrap())
    }

    /// Return a list of the currently mapped memory regions and their access permissions, based on
    /// the `/proc/pid/maps` file.
    pub fn maps(&self) -> ProcResult<Vec<MemoryMap>> {
        use std::io::{BufRead, BufReader};

        let file = proctry!(File::open(self.root.join("maps")));

        let reader = BufReader::new(file);

        ProcResult::Ok(
            reader
                .lines()
                .filter_map(|line| {
                    let line = line.unwrap();
                    let mut s = line.splitn(6, ' ');
                    let address = s.next().expect("maps::address");
                    let perms = s.next().expect("maps::perms");
                    let offset = s.next().expect("maps::offset");
                    let dev = s.next().expect("maps::dev");
                    let inode = s.next().expect("maps::inode");
                    let path = s.next().expect("maps::path");

                    let mmap = MemoryMap {
                        address: split_into_num(address, '-', 16),
                        perms: perms.to_string(),
                        offset: u64::from_str_radix(offset, 16).unwrap_or_else(|_| {
                            panic!("Failed to parse {} as an offset number", offset)
                        }),
                        dev: split_into_num(dev, ':', 16),
                        inode: u32::from_str_radix(inode, 10).unwrap_or_else(|_| {
                            panic!("Failed to parse {} as an inode number", inode)
                        }),
                        pathname: MMapPath::from(path),
                    };

                    Some(mmap)
                })
                .collect(),
        )
    }

    /// Gets a list of open file descriptors for a process
    pub fn fd(&self) -> ProcResult<Vec<FDInfo>> {
        use std::ffi::OsStr;
        use std::fs::read_link;

        let mut vec = Vec::new();

        for dir in proctry!(self.root.join("fd").read_dir()) {
            let entry = proctry!(dir);
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
        ProcResult::Ok(vec)
    }
}

pub fn all_processes() -> Vec<Process> {
    let mut v = Vec::new();
    for dir in std::fs::read_dir("/proc/").expect("No /proc/ directory") {
        if let Ok(entry) = dir {
            if let Ok(pid) = i32::from_str(&entry.file_name().to_string_lossy()) {
                if let ProcResult::Ok(prc) = Process::new(pid) {
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

    #[test]
    fn test_self_proc() {
        let myself = Process::myself().unwrap();
        println!("{:#?}", myself);
        println!("state: {:?}", myself.stat.state());
        println!("tty: {:?}", myself.stat.tty_nr());
        println!("flags: {:?}", myself.stat.flags());
        println!("starttime: {:#?}", myself.stat.starttime());
    }

    #[test]
    fn test_all() {
        for prc in all_processes() {
            prc.stat.flags();
            prc.stat.starttime();
            prc.cmdline();
            prc.environ();
            prc.cmdline();
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
        let io = myself.io().unwrap();
        println!("{:?}", io);
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

}
