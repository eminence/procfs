This subcrate contains tests that require a newer rust than our MSRV. 
By putting them in their own sub-crate, we can more easily test them selectively.

In particular, tests that involve the "backtrace" feature/crate require rust 1.38.