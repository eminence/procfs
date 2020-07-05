use std::path::{Path, PathBuf};

use super::{FileWrapper, ProcError, Stat};

/// A task (aka Thread) inside of a [`Process`](crate::process::Process)
///
/// Created by [`Process::tasks`](crate::process::Process::tasks), tasks in
/// general are similar to Processes and should have mostly the same fields.
///
/// Currently, only the `stat` field is populated/implemented.
#[derive(Debug, Clone)]
pub struct Task {
    /// The ID of the process that this task belongs to
    pub pid: i32,
    /// The task ID
    pub tid: i32,
    /// Task root: `/proc/<pid>/task/<tid>`
    pub(crate) root: PathBuf,
}

impl Task {
    /// Create a new `Task` inside of the process
    ///
    /// This API is designed to be ergonomic from inside of [`TasksIter`](super::TasksIter)
    pub(crate) fn from_rel_path(pid: i32, tid: &Path) -> Result<Task, ProcError> {
        let root = PathBuf::from(format!("/proc/{}/task", pid)).join(tid);
        Ok(Task {
            pid,
            tid: tid.file_name().unwrap().to_string_lossy().parse()?,
            root,
        })
    }

    /// Thread info from `/proc/<pid>/task/<tid>/stat`
    pub fn stat(&self) -> Result<Stat, ProcError> {
        Stat::from_reader(FileWrapper::open(self.root.join("stat"))?)
    }
}
