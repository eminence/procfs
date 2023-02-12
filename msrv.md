# MSRV for the `procfs` crate

The latest version of the `procfs` crate is only tested against the latest stable compiler.  However, it
may work with older compilers.

If you are using an older compiler and need a `procfs` bug fix on an older `procfs` version,
please open an issue on github, and we'll backport that bugfix.  If you need a
feature backported, please also open an issue to ask for a backport, but you may
be asked to help by opening a PR.

If you have any comments on this MSRV policy, please leave a comment
[on this issue](https://github.com/eminence/procfs/issues/223).

The table below attempts to list the latest version of `procfs` you can use, for
a given rustc compiler.


| Rust Version 	| `procfs` version 	| Notes 	|
|---	| --- 	|--- 	|
| Latest 	| Latest	| The latest version of procfs always supports the latest rustc compiler 	|
| 1.48 to 1.67 | 0.15 | [^1] |
| 1.34 to 1.54 | 0.13 | [^1] [^2] |


[^1]: `procfs` will support these older versions of rustc, but you'll need
to pin some of the `procfs` dependencies to older versions.  The dependencies that need pinning can change over time, but are likely `hex`, `bitflags`, and `flate2`.

[^2]: If you use the optional backtrace feature, you'll need rust 1.42 or newer.
