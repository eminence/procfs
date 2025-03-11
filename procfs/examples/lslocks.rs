use procfs::process::{FDTarget, Process};
use rustix::fs::AtFlags;
use std::path::Path;

fn main() {
    let myself = Process::myself().unwrap();
    let mountinfo = myself.mountinfo().unwrap();
    println!("{:18}{:13}{:13}{:13}{:12} Path", "Process", "PID", "Lock Type", "Mode", "Kind");
    println!("{}", "=".repeat(74));
    for lock in procfs::locks().unwrap() {
        lock.pid
            .and_then(|pid| Process::new(pid).ok())
            .and_then(|proc| proc.cmdline().ok())
            .and_then(|mut cmd| cmd.drain(..).next())
            .map_or_else(
                || {
                    print!("{:18}", "(undefined)");
                },
                |s| {
                    let p = Path::new(&s);
                    print!("{:18}", p.file_name().unwrap_or(p.as_os_str()).to_string_lossy());
                },
            );

        print!("{:<12} ", lock.pid.unwrap_or(-1));
        print!("{:12} ", lock.lock_type.as_str());
        print!("{:12} ", lock.mode.as_str());
        print!("{:12} ", lock.kind.as_str());

        // try to find the path for this inode
        let mut found = false;
        if let Some(pid) = lock.pid {
            if let Ok(fds) = Process::new(pid).and_then(|p| p.fd()) {
                for f in fds {
                    let fd = f.unwrap();
                    if let FDTarget::Path(p) = fd.target {
                        if let Ok(stat) = rustix::fs::statat(&rustix::fs::CWD, &p, AtFlags::empty()) {
                            if stat.st_ino as u64 == lock.inode {
                                print!("{}", p.display());
                                found = true;
                                break;
                            }
                        }
                    }
                }
            }
        }

        if !found {
            // we don't have a PID or we don't have permission to inspect the processes files, but we still have the device and inode
            // There's no way to look up a path from an inode, so just bring the device mount point
            for mount in &mountinfo {
                if format!("{}:{}", lock.devmaj, lock.devmin) == mount.majmin {
                    print!("{}...", mount.mount_point.display());
                    found = true;
                    break;
                }
            }
        }

        if !found {
            // still not found? print the device
            print!("{}:{}", lock.devmaj, lock.devmin);
        }

        println!();
    }
}
