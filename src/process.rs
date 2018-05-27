
use super::*;

use std::fs::DirEntry;
use std::fs::File;
use std::io::{self, ErrorKind, Read};
use std::str::FromStr;
use std::path::PathBuf;


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

impl<'a, 'b, I, U> ProcFrom<I> for U
where
    I: IntoIterator<Item = &'a str>,
    U: FromStr,
{
    fn from(i: I) -> U {
        let mut iter = i.into_iter();
        let val = iter.next().unwrap();
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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProcState {
    /// Running
    Running,
    /// Sleeping in an interruptible wait
    Sleeping,
    /// Waiting in uninterruptible disk sleep
    Waiting,
    /// Zombie
    Zombie,
    /// Stopped (on a signal)
    ///
    /// Or before Linux 2.6.33, trace stopped
    Stopped,
    /// Tracing stop (Linux 2.6.33 onward)
    Tracing,
    /// Dead
    Dead,
    /// Wakekill (Linux 2.6.33 to 3.13 only)
    Wakekill,
    /// Waking (Linux 2.6.33 to 3.13 only)
    Waking,
    /// Parked (Linux 3.9 to 3.13 only)
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
        ProcState::from_char(s.chars().next().unwrap()).ok_or("Failed to convert")
    }
}

//impl<'a, 'b, T> ProcFrom<&'b mut T> for ProcState where T: Iterator<Item=&'a str>, 'a: 'b {
//    fn from(s: &'b mut T) -> ProcState {
//        ProcState::from_str(s.next().unwrap()).unwrap()
//    }
//}

/// Status information about the process
#[derive(Debug, Clone)]
pub struct Stat {
    /// The process ID.
    pub pid: i32,
    /// The filename of the executable, in parentheses.  This is visible whether or not the executable is swapped out.
    pub comm: String,
    /// Process State.
    ///
    /// See [state()] to get the process state as an enum.
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
    pub tty_nr: i32,
    /// The ID of the foreground process group of the controlling terminal of the process.
    pub tpgid: i32,
    /// The kernel flags  word of the process.
    pub flags: u32,
    pub minflt: u64,
    pub cminflt: u64,
    pub majflt: u64,
    pub cmajflt: u64,
    pub utime: u64,
    pub stime: u64,
    pub cutime: i64,
    pub cstime: i64,
    pub priority: i64,
    /// The nice value (see `setpriority(2)`), a value in the range 19 (low priority) to -20 (high priority).
    pub nice: i64,
    pub num_threads: i64,
    pub itrealvalue: i64,
    /// The time the process started after system boot.
    ///
    /// In kernels before Linux 2.6, this value was expressed in  jiffies.  Since  Linux 2.6, the
    /// value is expressed in clock ticks (divide by `sysconf(_SC_CLK_TCK)`).
    pub starttime: i64,
    pub vsize: u64,
    pub rss: i64,
    pub rsslim: u64,
    pub startcode: u64,
    pub endcode: u64,
    pub startstack: u64,
    pub kstkesp: u64,
    pub kstkeip: u64,
    pub signal: u64,
    pub blocked: u64,
    pub sigignore: u64,
    pub sigcatch: u64,
    pub wchan: u64,
    pub nswap: u64,
    pub cnswap: u64,
    pub exit_signal: i32,
    pub processor: i32,
    pub rt_priority: u32,
    pub policy: u32,
    pub delayacct_blkio_ticks: u64,
    pub guest_time: u32,
    pub cguest_time: u32,
    pub start_data: usize,
    pub end_data: usize,
    pub start_brk: usize,
    pub arg_start: usize,
    pub arg_end: usize,
    pub env_start: usize,
    pub env_end: usize,
    pub exit_code: i32,
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
        let exit_signal = ProcFrom::from(&mut rest);
        let processor = ProcFrom::from(&mut rest);
        let rt_priority = ProcFrom::from(&mut rest);
        let policy = ProcFrom::from(&mut rest);
        let delayacct_blkio_ticks = ProcFrom::from(&mut rest);
        let guest_time = ProcFrom::from(&mut rest);
        let cguest_time = ProcFrom::from(&mut rest);
        let start_data = ProcFrom::from(&mut rest);
        let end_data = ProcFrom::from(&mut rest);
        let start_brk = ProcFrom::from(&mut rest);
        let arg_start = ProcFrom::from(&mut rest);
        let arg_end = ProcFrom::from(&mut rest);
        let env_start = ProcFrom::from(&mut rest);
        let env_end = ProcFrom::from(&mut rest);
        let exit_code = ProcFrom::from(&mut rest);

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
}

/// Represents a process
#[derive(Debug, Clone)]
pub struct Proc {
    pub stat: Stat,
    root: PathBuf
}


impl Proc {
    pub fn new(pid: pid_t) -> ProcResult<Proc> {
        let root = PathBuf::from("/proc").join(format!("{}", pid));
        let stat = Stat::from_reader(proctry!(File::open(root.join("stat")))).unwrap();

        ProcResult::Ok(Proc { root, stat })
    }

    pub fn myself() -> ProcResult<Proc> {
        let root = PathBuf::from("/proc/self");
        let stat = Stat::from_reader(proctry!(File::open(root.join("stat")))).unwrap();

        ProcResult::Ok(Proc { root, stat })
    }

    pub fn cmdline(&self) -> ProcResult<Vec<String>> {
        let mut buf = String::new();
        let mut f = proctry!(File::open(self.root.join("cmdline")));
        proctry!(f.read_to_string(&mut buf));
        ProcResult::Ok(buf.split('\0').filter_map(|s| if s.len() > 0 {Some(s.to_string())} else { None }).collect())
        
    }
}

pub fn all_processes() -> Vec<Proc> {
    let mut v = Vec::new();
    for dir in std::fs::read_dir("/proc/").unwrap() {
        let entry: DirEntry = dir.unwrap();
        if let Ok(pid) = i32::from_str(&entry.file_name().to_string_lossy()) {
            if let ProcResult::Ok(prc) = Proc::new(pid) {
                v.push(prc);
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
    fn test_self_stat() {
        let stat = Stat::from_reader(fs::File::open("/proc/self/stat").unwrap()).unwrap();
        println!("{:#?}", stat);
        println!("state: {:?}", stat.state());
        println!("tty: {:?}", stat.tty_nr());
        println!("flags: {:?}", stat.flags());
        println!("starttime: {:#?}", stat.starttime());
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
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

}
