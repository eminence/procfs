// List partitions listed in /proc/partitions

fn main() {
    println!("{:<5} {:<5} {:<11} {:<10}", "Major", "Minor", "Blocks", "Name");
    for part_entry in procfs::partitions().unwrap() {
        println!("{:<5} {:<5} {:<11} {:<10}", part_entry.major, part_entry.minor, part_entry.blocks, part_entry.name);
    }
}
