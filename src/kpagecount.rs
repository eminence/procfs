use std::{
    io::{BufReader, Read, Seek, SeekFrom},
    mem::size_of,
    ops::{Bound, Range, RangeBounds},
    path::Path,
};

use crate::FileWrapper;

use super::ProcResult;

/// Parse physical memory references accessing `/proc/kpagecount`
///
/// Require root or CAP_SYS_ADMIN
pub struct KPageCount {
    reader: BufReader<FileWrapper>,
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

        let reader = BufReader::new(FileWrapper::open(path)?);

        Ok(Self { reader })
    }

    /// Get the number of references to physical memory at `pfn`
    ///
    /// Return Err if pfn is not in RAM. See [crate::iomem()] for a list of valid physical RAM addresses
    ///
    /// See [crate::process::Process::pagemap] and [crate::process::MemoryPageFlags::get_page_frame_number]
    pub fn get_count_at_pfn(&mut self, pfn: u64) -> ProcResult<u64> {
        self.get_count_in_range(pfn..pfn + 1).map(|mut vec| vec.pop().unwrap())
    }

    /// Get the number of references to physical memory at for PFNs within range `page_range`
    ///
    /// Return Err if any pfn is not in RAM. See [crate::iomem()] for a list of valid physical RAM addresses
    ///
    /// See [crate::process::Process::pagemap] and [crate::process::MemoryPageFlags::get_page_frame_number]
    pub fn get_count_in_range(&mut self, page_range: Range<u64>) -> ProcResult<Vec<u64>> {
        // `start` is always included
        let start = match page_range.start_bound() {
            Bound::Included(v) => *v,
            Bound::Excluded(v) => *v + 1,
            Bound::Unbounded => 0,
        };

        // `end` is always excluded
        let end = match page_range.end_bound() {
            Bound::Included(v) => *v + 1,
            Bound::Excluded(v) => *v,
            Bound::Unbounded => std::u64::MAX,
        };

        let mut result: Vec<u64> = Vec::new();

        let start_position = start * size_of::<u64>() as u64;
        self.reader.seek(SeekFrom::Start(start_position))?;

        for _pfn in start..end {
            // Each entry is a 64 bits counter
            // 64 bits or 8 Bytes
            const ENTRY_SIZE: usize = 8;
            let mut buf = [0; ENTRY_SIZE];

            self.reader.read_exact(&mut buf)?;
            let page_references: u64 = u64::from_le_bytes(buf);

            result.push(page_references);
        }

        Ok(result)
    }
}
