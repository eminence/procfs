use std::io;

use super::convert_to_bytes;

/// This  file  reports  statistics about memory usage on the system.
#[derive(Debug)]
#[allow(non_snake_case)]
pub struct Meminfo {
    pub mem_total: u64,
    pub mem_free: u64,
    pub mem_available: Option<u64>,
    pub buffers: u64,
    pub cached: u64,
    pub swap_cached: u64,
    pub active: u64,
    pub inactive: u64,
    pub active_anon: Option<u64>,
    pub inactive_anon: Option<u64>,
    pub active_file: Option<u64>,
    pub inactive_file: Option<u64>,
    pub unevictable: Option<u64>,
    pub mlocked: Option<u64>,
    pub high_total: Option<u64>,
    pub high_free: Option<u64>,
    pub low_total: Option<u64>,
    pub low_free: Option<u64>,
    pub mmap_copy: Option<u64>,
    pub swap_total: u64,
    pub swap_free: u64,
    pub dirty: u64,
    pub writeback: u64,
    pub anon_pages: Option<u64>,
    pub mapped: u64,
    pub shmem: Option<u64>,
    pub slab: u64,
    pub s_reclaimable: Option<u64>,
    pub s_unreclaim: Option<u64>,
    pub kernel_stack: Option<u64>,
    pub page_tables: Option<u64>,
    pub quicklists: Option<u64>,
    pub nfs_unstable: Option<u64>,
    pub bounce: Option<u64>,
    pub writeback_tmp: Option<u64>,
    pub commit_limit: Option<u64>,
    pub committed_as: Option<u64>,
    pub vmalloc_total: u64,
    pub vmalloc_used: u64,
    pub vmalloc_chunk: u64,
    pub hardware_corrupted: Option<u64>,
    pub anon_hugepages: Option<u64>,
    pub shmem_hugepages: Option<u64>,
    pub shmem_pmd_mapped: Option<u64>,
    pub cma_total: Option<u64>,
    pub cma_free: Option<u64>,
    pub hugepages_total: Option<u64>,
    pub hugepages_free: Option<u64>,
    pub hugepages_rsvd: Option<u64>,
    pub hugepages_surp: Option<u64>,
    pub hugepagesize: Option<u64>,
    pub direct_map_4k: Option<u64>,
    pub direct_map_4M: Option<u64>,
    pub direct_map_2M: Option<u64>,
    pub direct_map_1G: Option<u64>,


}

impl Meminfo {

    pub fn new() -> Option<Meminfo> {
        use std::fs::File;

        let f = File::open("/proc/meminfo").ok()?;

        Meminfo::from_reader(f)

    }

    fn from_reader<R: io::Read>(mut r: R) -> Option<Meminfo> {


        use std::io::{BufRead,BufReader};
        use std::collections::HashMap;

        let reader = BufReader::new(r);
        let mut map = HashMap::new();

        for line in reader.lines() {
            let line = line.expect("Failed to read line");
            let mut s = line.split_whitespace();
            let field = s.next()?;
            let value = s.next()?;
            let unit = s.next(); // optional

            let value = u64::from_str_radix(value, 10).expect("Failed to parse number");
        
            let value = if let Some(unit) = unit {
                convert_to_bytes(value, unit)
            } else {
                value
            };

            map.insert(field[..field.len()-1].to_string(), value);


        }
        println!("{:#?}", map);

        // use 'remove' to move the value out of the hashmap
        // if there's anything still left in the map at the end, that 
        // means we probably have a bug/typo, or are out-of-date
        let meminfo = Meminfo {
            mem_total: map.remove("MemTotal").expect("MemTotal"),
            mem_free: map.remove("MemFree").expect("MemFree"),
            mem_available: map.remove("MemAvailable"),
            buffers: map.remove("Buffers").expect("Buffers"),
            cached: map.remove("Cached").expect("Cached"),
            swap_cached: map.remove("SwapCached").expect("SwapCached"),
            active: map.remove("Active").expect("Active"),
            inactive: map.remove("Inactive").expect("Inactive"),
            active_anon: map.remove("Active(anon)"),
            inactive_anon: map.remove("Inactive(anon)"),
            active_file: map.remove("Active(file)"),
            inactive_file: map.remove("Inactive(file)"),
            unevictable: map.remove("Unevictable"),
            mlocked: map.remove("Mlocked"),
            high_total: map.remove("HighTotal"),
            high_free: map.remove("HighFree"),
            low_total: map.remove("LowTotal"),
            low_free: map.remove("LowFree"),
            mmap_copy: map.remove("MmapCopy"),
            swap_total: map.remove("SwapTotal").expect("SwapTotal"),
            swap_free: map.remove("SwapFree").expect("SwapFree"),
            dirty: map.remove("Dirty").expect("Dirty"),
            writeback: map.remove("Writeback").expect("Writeback"),
            anon_pages: map.remove("AnonPages"),
            mapped: map.remove("Mapped").expect("Mapped"),
            shmem: map.remove("Shmem"),
            slab: map.remove("Slab").expect("Slab"),
            s_reclaimable: map.remove("SReclaimable"),
            s_unreclaim: map.remove("SUnreclaim"),
            kernel_stack: map.remove("KernelStack"),
            page_tables: map.remove("PageTables"),
            quicklists: map.remove("Quicklists"),
            nfs_unstable: map.remove("NFS_Unstable"),
            bounce: map.remove("Bounce"),
            writeback_tmp: map.remove("WritebackTmp"),
            commit_limit: map.remove("CommitLimit"),
            committed_as: map.remove("Committed_AS"),
            vmalloc_total: map.remove("VmallocTotal").expect("VmallocTotal"),
            vmalloc_used: map.remove("VmallocUsed").expect("VmallocUsed"),
            vmalloc_chunk: map.remove("VmallocChunk").expect("VmallocChunk"),
            hardware_corrupted: map.remove("HardwareCorrupted"),
            anon_hugepages: map.remove("AnonHugePages"),
            shmem_hugepages: map.remove("ShmemHugePages"),
            shmem_pmd_mapped: map.remove("ShmemPmdMapped"),
            cma_total: map.remove("CmaTotal"),
            cma_free: map.remove("CmaFree"),
            hugepages_total: map.remove("HugePages_Total"),
            hugepages_free: map.remove("HugePages_Free"),
            hugepages_rsvd: map.remove("HugePages_Rsvd"),
            hugepages_surp: map.remove("HugePages_Surp"),
            hugepagesize: map.remove("Hugepagesize"),
            direct_map_4k: map.remove("DirectMap4k"),
            direct_map_4M: map.remove("DirectMap4M"),
            direct_map_2M: map.remove("DirectMap2M"),
            direct_map_1G: map.remove("DirectMap1G"),





        };

        if !map.is_empty() {
            panic!("meminfo map is not empty: {:#?}", map);
        }

        Some(meminfo)

    }

}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_meminfo() {
        let meminfo = Meminfo::new();
        println!("{:#?}", meminfo);

    }
}
