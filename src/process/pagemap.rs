use crate::{FileWrapper, ProcResult};

use bitflags::bitflags;
use std::{
    io::{Read, Seek, SeekFrom},
    mem::size_of,
    ops::Range,
};

const fn genmask(high: usize, low: usize) -> u64 {
    let mask_bits = size_of::<u64>() * 8;
    (!0 - (1 << low) + 1) & (!0 >> (mask_bits - 1 - high))
}

// source: include/linux/swap.h
pub const MAX_SWAPFILES_SHIFT: usize = 5;

// source: fs/proc/task_mmu.c
bitflags! {
    pub struct SwapPageFlags: u64 {
        const SWAP_TYPE = genmask(MAX_SWAPFILES_SHIFT - 1, 0);
        const SWAP_OFFSET = genmask(54, MAX_SWAPFILES_SHIFT);
        const SOFT_DIRTY = 1 << 55;
        const MMAP_EXCLUSIVE = 1 << 56;
        const FILE = 1 << 61;
        const SWAP = 1 << 62;
        const PRESENT = 1 << 63;
    }
}

bitflags! {
    pub struct MemoryPageFlags: u64 {
        const PFN = genmask(54, 0);
        const SOFT_DIRTY = 1 << 55;
        const MMAP_EXCLUSIVE = 1 << 56;
        const FILE = 1 << 61;
        const SWAP = 1 << 62;
        const PRESENT = 1 << 63;
    }
}

#[derive(Debug)]
pub enum PageInfo {
    MemoryPage(MemoryPageFlags),
    SwapPage(SwapPageFlags),
}

impl PageInfo {
    pub(crate) fn parse_info(info: u64) -> Self {
        let flags = MemoryPageFlags::from_bits_truncate(info);

        if flags.contains(MemoryPageFlags::SWAP) {
            Self::SwapPage(SwapPageFlags::from_bits_truncate(info))
        } else {
            Self::MemoryPage(flags)
        }
    }
}

pub struct PageMap {
    file: FileWrapper,
}

impl PageMap {
    pub(crate) fn from_file_wrapper(file: FileWrapper) -> Self {
        Self { file }
    }

    fn parse_next_page_info(&mut self) -> ProcResult<PageInfo> {
        let mut info_bytes = [0; size_of::<u64>()];
        self.file.read_exact(&mut info_bytes)?;
        Ok(PageInfo::parse_info(u64::from_ne_bytes(info_bytes)))
    }

    pub fn get_info(&mut self, page_index: u64) -> ProcResult<PageInfo> {
        let position = page_index * size_of::<u64>() as u64;
        self.file.seek(SeekFrom::Start(position))?;
        self.parse_next_page_info()
    }

    pub fn get_range_info(&mut self, page_range: Range<u64>) -> ProcResult<Vec<PageInfo>> {
        let start_position = page_range.start * size_of::<u64>() as u64;
        self.file.seek(SeekFrom::Start(start_position))?;

        let mut page_infos = Vec::with_capacity((page_range.end - page_range.start) as usize);
        for _ in page_range {
            page_infos.push(self.parse_next_page_info()?);
        }

        Ok(page_infos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genmask() {
        let mask = genmask(3, 1);
        assert_eq!(mask, 0b1110);

        let mask = genmask(3, 0);
        assert_eq!(mask, 0b1111);

        let mask = genmask(63, 62);
        assert_eq!(mask, 0b11 << 62);
    }

    #[test]
    fn test_page_info() {
        let pagemap_entry: u64 = 0b1000000110000000000000000000000000000000000000000000000000000011;
        let info = PageInfo::parse_info(pagemap_entry);
        if let PageInfo::MemoryPage(memory_flags) = info {
            assert!(memory_flags
                .contains(MemoryPageFlags::PRESENT | MemoryPageFlags::MMAP_EXCLUSIVE | MemoryPageFlags::SOFT_DIRTY));
            assert_eq!((memory_flags & MemoryPageFlags::PFN).bits(), 0b11)
        } else {
            panic!("Wrong SWAP decoding");
        }

        let pagemap_entry: u64 = 0b1100000110000000000000000000000000000000000000000000000001100010;
        let info = PageInfo::parse_info(pagemap_entry);
        if let PageInfo::SwapPage(swap_flags) = info {
            assert!(
                swap_flags.contains(SwapPageFlags::PRESENT | SwapPageFlags::MMAP_EXCLUSIVE | SwapPageFlags::SOFT_DIRTY)
            );
            assert_eq!((swap_flags & SwapPageFlags::SWAP_TYPE).bits(), 0b10);
            assert_eq!(
                (swap_flags & SwapPageFlags::SWAP_OFFSET).bits() >> MAX_SWAPFILES_SHIFT,
                0b11
            );
        } else {
            panic!("Wrong SWAP decoding");
        }
    }
}
