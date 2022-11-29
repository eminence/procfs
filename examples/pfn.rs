//
// Print physical memory location for each memory mapping
// This requires CAP_SYS_ADMIN privilege, or root, otherwise physical memory addresses will be zero
//

use procfs::process::MMapPath;
use procfs::process::Process;

fn main() {
    if !rustix::process::geteuid().is_root() {
        println!("WARNING: Access to /proc/<PID>/pagemap requires root, re-run with sudo");
    }

    let page_size = procfs::page_size().unwrap();

    let process = Process::myself().expect("Unable to load myself!");

    let mut pagemap = process.pagemap().unwrap();
    let mem_map = process.maps().unwrap();

    for memory_map in mem_map {
        let mem_start = memory_map.address.0;
        let mem_end = memory_map.address.1;

        let index_start = (mem_start / page_size) as usize;
        let index_end = (mem_end / page_size) as usize;

        // can't scan Vsyscall, so skip it
        if memory_map.pathname == MMapPath::Vsyscall {
            continue;
        }

        println!("Memory mapping {:?}", memory_map);

        for index in index_start..index_end {
            let virt_mem = index * page_size as usize;
            let page_info = pagemap.get_info(index).unwrap();
            match page_info {
                procfs::process::PageInfo::MemoryPage(memory_page) => {
                    let pfn = memory_page.get_page_frame_number();
                    let phys_addr = pfn * page_size;
                    println!(
                        "virt_mem: 0x{:x}, pfn: 0x{:x}, phys_addr: 0x{:x}",
                        virt_mem, pfn, phys_addr
                    );
                }
                procfs::process::PageInfo::SwapPage(_) => (), // page is in swap
            }
        }
    }

    if !rustix::process::geteuid().is_root() {
        println!("\n\nWARNING: Access to /proc/<PID>/pagemap requires root, re-run with sudo");
    }
}
