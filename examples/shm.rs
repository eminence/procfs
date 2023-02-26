extern crate procfs;

/// List processes using posix shared memory segments

#[cfg(not(feature = "parsing_only"))]
fn main() {
    let shared_memory_vec = procfs::Shm::new().unwrap();

    for shared_memory in &shared_memory_vec {
        println!("key: {}, shmid: {}", shared_memory.key, shared_memory.shmid);
        println!("============");

        for prc in procfs::process::all_processes().unwrap() {
            let prc = prc.unwrap();
            match prc.smaps() {
                Ok(memory_maps) => {
                    for memory_map in &memory_maps {
                        if let procfs::process::MMapPath::Vsys(key) = memory_map.pathname {
                            if key == shared_memory.key && memory_map.inode == shared_memory.shmid {
                                println!("{}: {:?}", prc.pid, prc.cmdline().unwrap());
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }
        println!();
    }
}

#[cfg(feature = "parsing_only")]
fn main() {
    println!("This example must be run on linux");
}
