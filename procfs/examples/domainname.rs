use procfs::sys::kernel::{domainname, set_domainname};

fn main() {
    let current_domainname = domainname().unwrap();
    println!("Current domainname: {}", current_domainname);

    set_domainname("test.local").unwrap();
    println!("New domainname: {}", domainname().unwrap());

    set_domainname("").unwrap();
    println!("Removed domainname: {}", domainname().unwrap());

    set_domainname(&current_domainname).unwrap();
    println!("Reset domainname to original value: {}", domainname().unwrap());
}
