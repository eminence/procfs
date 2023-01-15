use std::{ops::Range, path::Path};

use rustix::fs::FileExt;

use crate::FileWrapper;

use super::ProcResult;

/// Parse physical memory references accessing `/proc/kpagecount`
///
/// Require root or CAP_SYS_ADMIN
pub struct KPageCount {
    reader: FileWrapper,
}

impl KPageCount {
    /// Get a parser from default `/proc/kpagecount`
    ///
    /// Return `Err` if process is not running as root or don't have CAP_SYS_ADMIN
    pub fn new() -> ProcResult<Self> {
        Self::from_custom_root("/proc")
    }

    /// Get a parser from custom `/proc`
    ///
    /// Return `Err` if process is not running as root or don't have CAP_SYS_ADMIN
    pub fn from_custom_root<P: AsRef<Path>>(root: P) -> ProcResult<Self> {
        let mut path = root.as_ref().to_path_buf();
        path.push("kpagecount");

        let reader = FileWrapper::open(path)?;

        Ok(Self { reader })
    }

    /// Get the number of references to physical memory at `pfn`
    ///
    /// Return Err if pfn is not in RAM. See [crate::iomem()] for a list of valid physical RAM addresses
    ///
    /// See [crate::process::Process::pagemap] and [crate::process::MemoryPageFlags::get_page_frame_number]
    pub fn get_count_at_pfn(&mut self, pfn: u64) -> ProcResult<u64> {
        // Each entry is a 64 bits counter
        // 64 bits or 8 Bytes
        const ENTRY_SIZE: usize = 8;
        let offset = pfn * ENTRY_SIZE as u64;

        let mut buf = [0; ENTRY_SIZE];
        self.reader.inner.read_exact_at(&mut buf, offset)?;
        let page_references: u64 = u64::from_le_bytes(buf);

        Ok(page_references)
    }

    /// Get the number of references to physical memory at for PFNs within range `page_range`
    ///
    /// Return Err if any pfn is not in RAM. See [crate::iomem()] for a list of valid physical RAM addresses
    ///
    /// See [crate::process::Process::pagemap] and [crate::process::MemoryPageFlags::get_page_frame_number]
    pub fn get_count_in_range(&mut self, page_range: Range<u64>) -> ProcResult<Vec<u64>> {
        // Each entry is a 64 bits counter
        // 64 bits or 8 Bytes
        const ENTRY_SIZE: usize = 8;

        let mut buf = [0; ENTRY_SIZE];

        let mut result: Vec<u64> = Vec::new();

        for pfn in page_range {
            let offset = pfn * ENTRY_SIZE as u64;
            self.reader.inner.read_exact_at(&mut buf, offset)?;
            let page_references: u64 = u64::from_le_bytes(buf);

            result.push(page_references);
        }

        Ok(result)
    }
}
