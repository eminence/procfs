//! Memory management tuning buffer and cache management
//!
//! The files in this directory can be used to tune
//! the operation of the virtual memory (VM) subsystem of the Linux kernel
//! and the write out of dirty data to disk.

use std::fmt;
use std::str;

use value::write_value;
use ProcResult;

procfs_value! {
    /// The amount of free memory in the system that should be reserved for users with the capability cap_sys_admin.
    ///
    /// # Example
    ///
    /// ```
    /// use procfs::sys::vm::admin_reserve_kbytes;
    ///
    /// assert_ne!(admin_reserve_kbytes().unwrap().get().unwrap(), 0);
    /// ```
    admin_reserve_kbytes: usize;
}

/// Force all zones are compacted such that free memory is available in contiguous blocks where possible.
///
/// This can be important for example in the allocation of huge pages
/// although processes will also directly compact memory as required.
///
/// Present only if the kernel was configured with CONFIG_COMPACTION.
pub fn compact_memory() -> ProcResult<()> {
    write_value("/proc/sys/vm/compact_memory", 1)
}

/// drop clean caches, dentries, and inodes from memory, causing that memory to become free.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DropCache {
    /// default
    Default = 0,
    /// free pagecache
    PageCache = 1,
    /// free dentries and inodes
    Inodes = 2,
    /// free pagecache, dentries and inodes
    All = 3,
    /// disable
    Disable = 4,
}

impl fmt::Display for DropCache {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                DropCache::Default => 0,
                DropCache::PageCache => 1,
                DropCache::Inodes => 2,
                DropCache::All => 3,
                DropCache::Disable => 4,
            }
        )
    }
}

impl str::FromStr for DropCache {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse()
            .map_err(|_| "Fail to parse drop cache")
            .and_then(|n| match n {
                0 => Ok(DropCache::Default),
                1 => Ok(DropCache::PageCache),
                2 => Ok(DropCache::Inodes),
                3 => Ok(DropCache::All),
                4 => Ok(DropCache::Disable),
                _ => Err("Unknown drop cache value"),
            })
    }
}

procfs_value! {
    /// Causes the kernel to drop clean caches, dentries, and inodes from memory,
    /// causing that memory to become free.
    ///
    /// This can be useful for memory management testing and performing reproducible filesystem benchmarks.
    /// Because writing to this file causes the benefits of caching to be lost,
    /// it can degrade overall system performance.
    ///
    /// # Example
    ///
    /// ```
    /// use procfs::sys::vm::{drop_caches, DropCache};
    ///
    /// if let Ok(drop_caches) = drop_caches() {
    ///     if drop_caches.writeable() {
    ///         drop_caches.set(DropCache::Default).unwrap();
    ///     }
    /// }
    /// ```
    @writeonly
    drop_caches: DropCache;

    /// The maximum number of memory map areas a process may have.
    ///
    /// Memory map areas are used as a side-effect of calling malloc,
    /// directly by mmap, mprotect, and madvise, and also when loading shared libraries.
    ///
    /// # Example
    ///
    /// ```
    /// use procfs::sys::vm::max_map_count;
    ///
    /// assert_ne!(max_map_count().unwrap().get().unwrap(), 0);
    /// ```
    max_map_count: u64;

    /// If nonzero, this disables the new 32-bit memory-mapping layout;
    /// the kernel will use the legacy (2.4) layout for all processes.
    legacy_va_layout: isize;
}
