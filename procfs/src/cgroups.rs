use super::process::Process;
use crate::ProcResult;
pub use procfs_core::{CGroupController, ProcessCgroup};

/// Information about the cgroup controllers that are compiled into the kernel
///
/// (since Linux 2.6.24)
pub fn cgroups() -> ProcResult<Vec<CGroupController>> {
    CGroupController::cgroup_controllers_from_reader(std::fs::File::open("/proc/cgroups")?)
}

impl Process {
    /// Describes control groups to which the process with the corresponding PID belongs.
    ///
    /// The displayed information differs for cgroupsversion 1 and version 2 hierarchies.
    pub fn cgroups(&self) -> ProcResult<Vec<ProcessCgroup>> {
        ProcessCgroup::cgroups_from_reader(self.open_relative("cgroup")?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroups() {
        let groups = cgroups().unwrap();
        println!("{:?}", groups);
    }

    #[test]
    fn test_process_cgroups() {
        let myself = Process::myself().unwrap();
        let groups = myself.cgroups();
        println!("{:?}", groups);
    }
}
