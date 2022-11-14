//! For each interface, display the number of bytes sent and received, along with a data rate

fn main() {
    let delay = std::time::Duration::from_secs(2);

    let mut cnt = 3;
    println!("----- dev_status -----");
    let mut prev_stats = procfs::net::dev_status().unwrap();
    let mut prev_now = std::time::Instant::now();
    while cnt > 0 {
        std::thread::sleep(delay);
        let now = std::time::Instant::now();
        let dev_stats = procfs::net::dev_status().unwrap();

        // calculate diffs from previous
        let dt = (now - prev_now).as_millis() as f32 / 1000.0;

        let mut stats: Vec<_> = dev_stats.values().collect();
        stats.sort_by_key(|s| &s.name);
        println!();
        println!(
            "{:>16}: {:<20}               {:<20} ",
            "Interface", "bytes recv", "bytes sent"
        );
        println!(
            "{:>16}  {:<20}               {:<20}",
            "================", "====================", "===================="
        );
        for stat in stats {
            println!(
                "{:>16}: {:<20}  {:>6.1} kbps  {:<20}  {:>6.1} kbps ",
                stat.name,
                stat.recv_bytes,
                (stat.recv_bytes - prev_stats.get(&stat.name).unwrap().recv_bytes) as f32 / dt / 1000.0,
                stat.sent_bytes,
                (stat.sent_bytes - prev_stats.get(&stat.name).unwrap().sent_bytes) as f32 / dt / 1000.0
            );
        }
        prev_stats = dev_stats;
        prev_now = now;
        cnt -= 1;
    }

    println!();
    println!("================================================================================");
    println!();

    cnt = 3;
    println!("----- dev_status_with_pid 1 -----");
    let mut prev_stats_with_pid = procfs::net::dev_status_with_pid(1).unwrap();
    let mut prev_now = std::time::Instant::now();
    while cnt > 0 {
        std::thread::sleep(delay);
        let now = std::time::Instant::now();
        let dev_stats_with_pid = procfs::net::dev_status_with_pid(1).unwrap();

        // calculate diffs from previous
        let dt = (now - prev_now).as_millis() as f32 / 1000.0;

        let mut stats_with_pid: Vec<_> = dev_stats_with_pid.values().collect();
        stats_with_pid.sort_by_key(|s| &s.name);
        println!();
        println!(
            "{:>16}: {:<20}               {:<20} ",
            "Interface", "bytes recv", "bytes sent"
        );
        println!(
            "{:>16}  {:<20}               {:<20}",
            "================", "====================", "===================="
        );
        for stat in stats_with_pid {
            println!(
                "{:>16}: {:<20}  {:>6.1} kbps  {:<20}  {:>6.1} kbps ",
                stat.name,
                stat.recv_bytes,
                (stat.recv_bytes - prev_stats_with_pid.get(&stat.name).unwrap().recv_bytes) as f32 / dt / 1000.0,
                stat.sent_bytes,
                (stat.sent_bytes - prev_stats_with_pid.get(&stat.name).unwrap().sent_bytes) as f32 / dt / 1000.0
            );
        }

        prev_stats_with_pid = dev_stats_with_pid;
        prev_now = now;
        cnt -= 1;
    }
}
