use procfs::sys::kernel::{hostname, set_hostname};

fn main() {
    let current_hostname = hostname().unwrap();
    println!("Current hostname: {}", current_hostname);

    set_hostname("new-hostname").unwrap();
    println!("New hostname: {}", hostname().unwrap());

    set_hostname(&current_hostname).unwrap();
    println!("Reset hostname to original value: {}", hostname().unwrap());
}
