use super::*;

use std::fs::DirEntry;
use std::fs::File;
use std::io::{self, ErrorKind, Read};
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
        const PF_IDLE = 0x00000002;
        /// Getting shut down
        const PF_EXITING = 0x00000004;
        /// PI exit done on shut down
        const PF_EXITPIDONE = 0x00000008;
        /// I'm a virtual CPU
        const PF_VCPU = 0x00000010;
        /// I'm a workqueue worker
        const PF_WQ_WORKER = 0x00000020;
        /// Forked but didn't exec
        const PF_FORKNOEXEC = 0x00000040;
        /// Process policy on mce errors;
        const PF_MCE_PROCESS = 0x00000080;
        /// Used super-user privileges
        const PF_SUPERPRIV = 0x00000100;
        /// Dumped core
        const PF_DUMPCORE = 0x00000200;
        /// Killed by a signal
        const PF_SIGNALED = 0x00000400;
        ///Allocating memory
        const PF_MEMALLOC = 0x00000800;
        /// set_user() noticed that RLIMIT_NPROC was exceeded
        const PF_NPROC_EXCEEDED = 0x00001000;
        /// If unset the fpu must be initialized before use
        const PF_USED_MATH = 0x00002000;
         /// Used async_schedule*(), used by module init
        const PF_USED_ASYNC = 0x00004000;
        ///  This thread should not be frozen
        const PF_NOFREEZE = 0x00008000;
        /// Frozen for system suspend
        const PF_FROZEN = 0x00010000;
        //// I am kswapd
        const PF_KSWAPD = 0x00020000;
        /// All allocation requests will inherit GFP_NOFS
        const PF_MEMALLOC_NOFS = 0x00040000;
        /// All allocation requests will inherit GFP_NOIO
        const PF_MEMALLOC_NOIO = 0x00080000;
        /// Throttle me less: I clean memory
        const PF_LESS_THROTTLE = 0x00100000;
        /// I am a kernel thread
        const PF_KTHREAD = 0x00200000;
        /// Randomize virtual address space
        const PF_RANDOMIZE = 0x00400000;
        /// Allowed to write to swap
        const PF_SWAPWRITE = 0x00800000;
        /// Userland is not allowed to meddle with cpus_allowed
        const PF_NO_SETAFFINITY = 0x04000000;
        /// Early kill for mce process policy
        const PF_MCE_EARLY = 0x08000000;
        /// Thread belongs to the rt mutex tester
        const PF_MUTEX_TESTER = 0x20000000;
        /// Freezer should not count it as freezable
        const PF_FREEZER_SKIP = 0x40000000;
        /// This thread called freeze_processes() and should not be frozen
        const PF_SUSPEND_TASK = 0x80000000;

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
            Err(..) => panic!(format!("Failed to convert")),
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
    /// See [tty_nr()] to get this value decoded into a (major, minor) tuple
    pub tty_nr: i32,
    /// The ID of the foreground process group of the controlling terminal of the process.
    pub tpgid: i32,
    /// The kernel flags  word of the process.
    ///
    /// For bit meanings, see the PF_* defines in  the  Linux  kernel  source  file
    /// `include/linux/sched.h`.  
    ///
    /// See [flags()] to get a `StatField` object.
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
    /// (divide by [`TICKS_PER_SECOND`](struct.TICKS_PER_SECOND.html)).
    ///
    /// This includes guest time, guest_time (time spent running a virtual CPU, see below), so that
    /// applications that are not aware of the guest time field  do not lose that time from their
    /// calculations.
    pub utime: u64,
    /// Amount of time that this process has been scheduled in kernel mode, measured in clock ticks
    /// (divide by `TICKS_PER_SECOND`).
    pub stime: u64,

    /// Amount  of  time  that  this  process's  waited-for  children  have  been  scheduled  in
    /// user  mode,  measured  in clock ticks (divide by `[TICKS_PER_SECOND]`).
    ///
    /// This includes guest time, cguest_time (time spent running a virtual CPU, see below).
    pub cutime: i64,

    /// Amount of time that this process's waited-for  children  have  been  scheduled  in  kernel
    /// mode,  measured  in  clock  ticks  (divide  by `[TICKS_PER_SECOND]`).
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
    /// not provide information on real-time
    ///                         signals; use /proc/[pid]/status instead.
    pub signal: u64,
    /// The bitmap of blocked signals, displayed as a decimal number.  Obsolete, because it does
    /// not provide information on  real-time
    ///                         signals; use /proc/[pid]/status instead.
    pub blocked: u64,
    /// The  bitmap of ignored signals, displayed as a decimal number.  Obsolete, because it does
    /// not provide information on real-time
    ///                         signals; use /proc/[pid]/status instead.
    pub sigignore: u64,
    /// The bitmap of caught signals, displayed as a decimal number.  Obsolete, because it does not
    /// provide information  on  real-time
    ///                         signals; use /proc/[pid]/status instead.
    pub sigcatch: u64,
    /// This  is  the  "channel"  in which the process is waiting.  It is the address of a location
    /// in the kernel where the process is
    ///                         sleeping.  The corresponding symbolic name can be found in
    ///                         /proc/[pid]/wchan.
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
    /// Guest time of the process (time spent running a virtual CPU for a guest operating system), measured  in  clock  ticks
    ///
    /// (divide by `TICKS_PER_SECOND`)
    ///
    /// (since Linux 2.6.24)
    pub guest_time: Option<u32>,
    /// Guest time of the process's children, measured in clock ticks (divide by `TICKS_PER_SECOND`).
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

macro_rules! since_kernel {
    ($a:tt - $b:tt - $c:tt, $e:expr) => {
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

        let exit_signal = since_kernel!(2-1-22, ProcFrom::from(&mut rest));
        let processor = since_kernel!(2-2-8, ProcFrom::from(&mut rest));
        let rt_priority = since_kernel!(2-5-19, ProcFrom::from(&mut rest));
        let policy = since_kernel!(2-5-19, ProcFrom::from(&mut rest));
        let delayacct_blkio_ticks = since_kernel!(2-6-18, ProcFrom::from(&mut rest));
        let guest_time = since_kernel!(2-6-24, ProcFrom::from(&mut rest));
        let cguest_time = since_kernel!(2-6-24, ProcFrom::from(&mut rest));
        let start_data = since_kernel!(3-3-0, ProcFrom::from(&mut rest));
        let end_data = since_kernel!(3-3-0, ProcFrom::from(&mut rest));
        let start_brk = since_kernel!(3-3-0, ProcFrom::from(&mut rest));
        let arg_start = since_kernel!(3-5-0, ProcFrom::from(&mut rest));
        let arg_end = since_kernel!(3-5-0, ProcFrom::from(&mut rest));
        let env_start = since_kernel!(3-5-0, ProcFrom::from(&mut rest));
        let env_end = since_kernel!(3-5-0, ProcFrom::from(&mut rest));
        let exit_code = since_kernel!(3-5-0, ProcFrom::from(&mut rest));

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

/// Represents a process in `/proc/<pid>`
#[derive(Debug, Clone)]
pub struct Proc {
    pub stat: Stat,
    /// The user id of the owner of this process
    pub owner: u32,
    root: PathBuf,
}

impl Proc {
    pub fn new(pid: pid_t) -> ProcResult<Proc> {
        let root = PathBuf::from("/proc").join(format!("{}", pid));
        let stat = Stat::from_reader(proctry!(File::open(root.join("stat")))).unwrap();

        let md = proctry!(std::fs::metadata(&root));

        ProcResult::Ok(Proc {
            root,
            stat,
            owner: md.st_uid(),
        })
    }

    pub fn myself() -> ProcResult<Proc> {
        let root = PathBuf::from("/proc/self");
        let stat = Stat::from_reader(proctry!(File::open(root.join("stat")))).unwrap();
        let md = proctry!(std::fs::metadata(&root));

        ProcResult::Ok(Proc {
            root,
            stat,
            owner: md.st_uid(),
        })
    }

    pub fn cmdline(&self) -> ProcResult<Vec<String>> {
        let mut buf = String::new();
        let mut f = proctry!(File::open(self.root.join("cmdline")));
        proctry!(f.read_to_string(&mut buf));
        ProcResult::Ok(
            buf.split('\0')
                .filter_map(|s| {
                    if s.len() > 0 {
                        Some(s.to_string())
                    } else {
                        None
                    }
                })
                .collect(),
        )
    }

    pub fn pid(&self) -> pid_t {
        self.stat.pid
    }

    /// Is this process still alive?
    pub fn is_alive(&self) -> bool {
        match Proc::new(self.pid()) {
            ProcResult::Ok(prc) => {
                // assume that the command line and uid don't change during a processes lifetime
                // i.e. if they are different, a new process has the same PID as `self` and so `self` is not considered alive
                prc.stat.comm == self.stat.comm && prc.owner == self.owner
            }
            _ => false,
        }
    }
}

pub fn all_processes() -> Vec<Proc> {
    let mut v = Vec::new();
    for dir in std::fs::read_dir("/proc/").expect("No /proc/ directory") {
        if let Ok(entry) = dir {
            if let Ok(pid) = i32::from_str(&entry.file_name().to_string_lossy()) {
                if let ProcResult::Ok(prc) = Proc::new(pid) {
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
    use std::fs;

    #[test]
    fn test_self_proc() {
        let myself = Proc::myself().unwrap();
        println!("{:#?}", myself);
        println!("state: {:?}", myself.stat.state());
        println!("tty: {:?}", myself.stat.tty_nr());
        println!("flags: {:?}", myself.stat.flags());
        println!("starttime: {:#?}", myself.stat.starttime());
    }

    #[test]
    fn test_all() {
        for prc in all_processes() {
            println!("{:?}", prc);
            println!("{:?}", prc.stat.flags());
            println!("{:?}", prc.stat.starttime());
            println!("{:?}", prc.cmdline().unwrap());
        }
    }

    #[test]
    fn test_proc_alive() {
        let myself = Proc::myself().unwrap();
        assert!(myself.is_alive());
    }

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

}
