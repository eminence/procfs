// List mountpoints listed in /proc/mounts

fn main() {
    for mount_entry in procfs::mounts().unwrap() {
        println!("{mount_entry:?}");
    }
}
