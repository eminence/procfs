procfs
======

Click here to view the documentation for this crate:
[Documentation](https://docs.rs/procfs)

This crate is an interface to the `proc` pseudo-filesystem on linux, which is normally mounted as `/proc`.
Long-term, this crate aims to be fairly feature complete, but at the moment not all files are exposed.
See the docs for info on what's supported.

## Examples

Here's a small example that prints out all processes that are running on the same tty as the calling
process.  This is very similar to what "ps" does in its default mode:

```rust
extern crate procfs;

fn main() {
    let me = procfs::Process::myself().unwrap();
    let tps = procfs::ticks_per_second().unwrap();

    println!("{: >5} {: <8} {: >8} {}", "PID", "TTY", "TIME", "CMD");

    let tty = format!("pty/{}", me.stat.tty_nr().1);
    for prc in procfs::all_processes() {
        if prc.stat.tty_nr == me.stat.tty_nr {
            // total_time is in seconds
            let total_time =
                (prc.stat.utime + prc.stat.stime) as f32 / (tps as f32);
            println!(
                "{: >5} {: <8} {: >8} {}",
                prc.stat.pid, tty, total_time, prc.stat.comm
            );
        }
    }
}
```


## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Contriutions are welcome, especially in the areas of documentation and testing on older kernels.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

