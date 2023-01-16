use crate::{FileWrapper, ProcResult};

use bitflags::bitflags;
use std::{
    io::{BufReader, Read, Seek, SeekFrom},
    mem::size_of,
    ops::{Bound, RangeBounds},
    path::Path,
};

#[cfg(feature = "serde1")]
use serde::{Deserialize, Serialize};

//const fn genmask(high: usize, low: usize) -> u64 {
//    let mask_bits = size_of::<u64>() * 8;
//    (!0 - (1 << low) + 1) & (!0 >> (mask_bits - 1 - high))
//}

bitflags! {
    /// Represents the fields and flags in a page table entry for a memory page.
    #[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
    pub struct PhysicalPageFlags: u64 {
        /// The page is being locked for exclusive access, e.g. by undergoing read/write IO
        const LOCKED = 1 << 0;
        /// IO error occurred
        const ERROR = 1 << 1;
        /// The page has been referenced since last LRU list enqueue/requeue
        const REFERENCED = 1 << 2;
        /// The page has up-to-date data. ie. for file backed page: (in-memory data revision >= on-disk one)
        const UPTODATE = 1 << 3;
        /// The page has been written to, hence contains new data. i.e. for file backed page: (in-memory data revision > on-disk one)
        const DIRTY = 1 << 4;
        /// The page is in one of the LRU lists
        const LRU = 1 << 5;
        /// The page is in the active LRU list
        const ACTIVE = 1 << 6;
        /// The page is managed by the SLAB/SLOB/SLUB/SLQB kernel memory allocator. When compound page is used, SLUB/SLQB will only set this flag on the head page; SLOB will not flag it at all
        const SLAB = 1 << 7;
        /// The page is being synced to disk
        const WRITEBACK = 1 << 8;
        /// The page will be reclaimed soon after its pageout IO completed
        const RECLAIM = 1 << 9;
        /// A free memory block managed by the buddy system allocator. The buddy system organizes free memory in blocks of various orders. An order N block has 2^N physically contiguous pages, with the BUDDY flag set for and _only_ for the first page
        const BUDDY = 1 << 10;
        /// A memory mapped page
        const MMAP = 1 << 11;
        /// A memory mapped page that is not part of a file
        const ANON = 1 << 12;
        /// The page is mapped to swap space, i.e. has an associated swap entry
        const SWAPCACHE = 1 << 13;
        /// The page is backed by swap/RAM
        const SWAPBACKED = 1 << 14;
        /// A compound page with order N consists of 2^N physically contiguous pages. A compound page with order 2 takes the form of “HTTT”, where H donates its head page and T donates its tail page(s). The major consumers of compound pages are hugeTLB pages (<https://www.kernel.org/doc/html/latest/admin-guide/mm/hugetlbpage.html#hugetlbpage>), the SLUB etc. memory allocators and various device drivers. However in this interface, only huge/giga pages are made visible to end users
        const COMPOUND_HEAD = 1 << 15;
        /// A compound page tail (see description above)
        const COMPOUND_TAIL = 1 << 16;
        /// This is an integral part of a HugeTLB page
        const HUGE = 1 << 17;
        /// The page is in the unevictable (non-)LRU list It is somehow pinned and not a candidate for LRU page reclaims, e.g. ramfs pages, shmctl(SHM_LOCK) and mlock() memory segments
        const UNEVICTABLE = 1 << 18;
        /// Hardware detected memory corruption on this page: don’t touch the data!
        const HWPOISON = 1 << 19;
        /// No page frame exists at the requested address
        const NOPAGE = 1 << 20;
        /// Identical memory pages dynamically shared between one or more processes
        const KSM = 1 << 21;
        /// Contiguous pages which construct transparent hugepages
        const THP = 1 << 22;
        /// The page is logically offline
        const OFFLINE = 1 << 23;
        /// Zero page for pfn_zero or huge_zero page
        const ZERO_PAGE = 1 << 24;
        /// The page has not been accessed since it was marked idle (see <https://www.kernel.org/doc/html/latest/admin-guide/mm/idle_page_tracking.html#idle-page-tracking>). Note that this flag may be stale in case the page was accessed via a PTE. To make sure the flag is up-to-date one has to read /sys/kernel/mm/page_idle/bitmap first
        const IDLE = 1 << 25;
        /// The page is in use as a page table
        const PGTABLE = 1 << 26;

    }
}

impl PhysicalPageFlags {
    pub(crate) fn parse_info(info: u64) -> Self {
        PhysicalPageFlags::from_bits_truncate(info)
    }
}

/// Parse physical memory flags accessing `/proc/kpageflags`.
///
/// Require root or CAP_SYS_ADMIN
pub struct KPageFlags {
    reader: BufReader<FileWrapper>,
}

impl KPageFlags {
    /// Get a parser from default `/proc/kpageflags`
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
        path.push("kpageflags");

        let reader = BufReader::new(FileWrapper::open(path)?);

        Ok(Self { reader })
    }

    /// Retrieve information in the page table entry for the PFN (page frame number) at index `page_index`.
    /// If you need to retrieve multiple PFNs, opt for [Self::get_range_info()] instead.
    ///
    /// Return Err if the PFN is not in RAM (see [crate::iomem()]):
    /// Io(Error { kind: UnexpectedEof, message: "failed to fill whole buffer" }, None)
    pub fn get_info(&mut self, page_index: u64) -> ProcResult<PhysicalPageFlags> {
        self.get_range_info(page_index..page_index + 1)
            .map(|mut vec| vec.pop().unwrap())
    }

    /// Retrieve information in the page table entry for the PFNs within range `page_range`.
    ///
    /// Return Err if any PFN is not in RAM (see [crate::iomem()]):
    /// Io(Error { kind: UnexpectedEof, message: "failed to fill whole buffer" }, None)
    pub fn get_range_info(&mut self, page_range: impl RangeBounds<u64>) -> ProcResult<Vec<PhysicalPageFlags>> {
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
            Bound::Unbounded => std::u64::MAX / crate::page_size(),
        };

        let start_position = start * size_of::<u64>() as u64;
        self.reader.seek(SeekFrom::Start(start_position))?;

        let mut page_infos = Vec::with_capacity((end - start) as usize);
        for _ in start..end {
            let mut info_bytes = [0; size_of::<u64>()];
            self.reader.read_exact(&mut info_bytes)?;
            page_infos.push(PhysicalPageFlags::parse_info(u64::from_ne_bytes(info_bytes)));
        }

        Ok(page_infos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kpageflags_parsing() {
        let pagemap_entry: u64 = 0b0000000000000000000000000000000000000000000000000000000000000001;
        let info = PhysicalPageFlags::parse_info(pagemap_entry);
        assert!(info == PhysicalPageFlags::LOCKED);
    }
}
