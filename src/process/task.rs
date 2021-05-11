use std::path::{Path, PathBuf};

use super::{FileWrapper, Io, Schedstat, Stat, Status};
use std::os::unix::io::{RawFd};
use crate::{NixErrorExt, ProcResult};
use libc::pid_t;

/// A task (aka Thread) inside of a [`Process`](crate::process::Process)
///
/// Created by [`Process::tasks`](crate::process::Process::tasks), tasks in
/// general are similar to Processes and should have mostly the same fields.
#[derive(Debug, Clone)]
pub struct Task {
    pub fd: RawFd,
    /// The ID of the process that this task belongs to
    pub pid: pid_t,
    /// The task ID
    pub tid: pid_t,
    /// Task root: `/proc/<pid>/task/<tid>`
    pub(crate) root: PathBuf,
}

impl Drop for Task {
    fn drop(&mut self) {
        nix::unistd::close(self.fd).ok();
    }
}

impl Task {
    /// Create a new `Task` inside of the process
    ///
    /// This API is designed to be ergonomic from inside of [`TasksIter`](super::TasksIter)
    pub(crate) fn from_process_at<P: AsRef<Path>, Q: AsRef<Path>>(base: P, dirfd: RawFd, path: Q, pid: pid_t, tid: pid_t) -> ProcResult<Task> {
        use nix::sys::stat::Mode;
        use nix::fcntl::OFlag;

        let p = path.as_ref();
        let root = base.as_ref().join(p);
        let fd = wrap_io_error!(
            root,
            nix::fcntl::openat(dirfd, p, OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::empty())
                .map_err(|err| err.into_io_error()))?;

        Ok(Task {
            fd,
            pid,
            tid,
            root,
        })
    }

    /// Thread info from `/proc/<pid>/task/<tid>/stat`
    ///
    /// Many of the returned fields will be the same as the parent process, but some fields like `utime` and `stime` will be per-task
    pub fn stat(&self) -> ProcResult<Stat> {
        Stat::from_reader(FileWrapper::open_at(&self.root, self.fd, "stat")?)
    }

    /// Thread info from `/proc/<pid>/task/<tid>/status`
    ///
    /// Many of the returned fields will be the same as the parent process
    pub fn status(&self) -> ProcResult<Status> {
        Status::from_reader(FileWrapper::open_at(&self.root, self.fd, "status")?)
    }

    /// Thread IO info from `/proc/<pid>/task/<tid>/io`
    ///
    /// This data will be unique per task.
    pub fn io(&self) -> ProcResult<Io> {
        Io::from_reader(FileWrapper::open_at(&self.root, self.fd, "io")?)
    }

    /// Thread scheduler info from `/proc/<pid>/task/<tid>/schedstat`
    ///
    /// This data will be unique per task.
    pub fn schedstat(&self) -> ProcResult<Schedstat> {
        Schedstat::from_reader(FileWrapper::open_at(&self.root, self.fd, "schedstat")?)
    }
}

#[cfg(test)]
mod tests {
    use crate::process::Io;
    use std::sync::{Arc, Barrier};

    #[test]
    #[cfg(not(tarpaulin))] // this test is unstable under tarpaulin, and i'm yet sure why
    fn test_task() {
        use std::io::Read;

        let me = crate::process::Process::myself().unwrap();

        let (work_barrier, w_a, w_b) = {
            let b = Arc::new(Barrier::new(3));
            (b.clone(), b.clone(), b)
        };
        let (done_barrier, d_a, d_b) = {
            let b = Arc::new(Barrier::new(3));
            (b.clone(), b.clone(), b)
        };

        let bytes_to_read = 2_000_000;

        // create a new task to do some work
        let join_a = std::thread::Builder::new()
            .name("one".to_owned())
            .spawn(move || {
                let mut vec = Vec::new();
                let zero = std::fs::File::open("/dev/zero").unwrap();

                zero.take(bytes_to_read).read_to_end(&mut vec).unwrap();
                assert_eq!(vec.len(), bytes_to_read as usize);

                // spin for about 52 ticks (utime accounting isn't perfectly accurate)
                let dur = std::time::Duration::from_millis(52 * (1000 / crate::ticks_per_second().unwrap()) as u64);
                let start = std::time::Instant::now();
                while start.elapsed() <= dur {
                    // spin
                }

                w_a.wait();
                d_a.wait()
            })
            .unwrap();

        // create a new task that does nothing
        let join_b = std::thread::Builder::new()
            .name("two".to_owned())
            .spawn(move || {
                w_b.wait();
                d_b.wait();
            })
            .unwrap();

        work_barrier.wait();

        let mut found_one = false;
        let mut found_two = false;
        let mut summed_io = Io {
            rchar: 0,
            wchar: 0,
            syscr: 0,
            syscw: 0,
            read_bytes: 0,
            write_bytes: 0,
            cancelled_write_bytes: 0,
        };
        for task in me.tasks().unwrap() {
            let task = task.unwrap();
            let stat = task.stat().unwrap();
            let status = task.status().unwrap();
            let io = task.io().unwrap();

            summed_io.rchar += io.rchar;
            summed_io.wchar += io.wchar;
            summed_io.syscr += io.syscr;
            summed_io.syscw += io.syscw;
            summed_io.read_bytes += io.read_bytes;
            summed_io.write_bytes += io.write_bytes;
            summed_io.cancelled_write_bytes += io.cancelled_write_bytes;

            if stat.comm == "one" && status.name == "one" {
                found_one = true;
                assert!(io.rchar >= bytes_to_read);
                assert!(stat.utime >= 1, "utime({}) too small", stat.utime);
            }
            if stat.comm == "two" && status.name == "two" {
                found_two = true;
                assert_eq!(io.rchar, 0);
                assert_eq!(stat.utime, 0);
            }
        }

        let proc_io = me.io().unwrap();
        // these should be mostly the same (though creating the IO struct in the above line will cause some IO to occur)
        println!("{:?}", summed_io);
        println!("{:?}", proc_io);

        // signal the threads to exit
        done_barrier.wait();
        join_a.join().unwrap();
        join_b.join().unwrap();

        assert!(found_one);
        assert!(found_two);
    }
}
