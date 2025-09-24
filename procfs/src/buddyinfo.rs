use procfs_core::{BuddyInfo, ProcResult};

use crate::Current;

impl Current for BuddyInfo {
    const PATH: &'static str = "/proc/buddyinfo";
}

pub fn buddyinfo() -> ProcResult<BuddyInfo> {
    BuddyInfo::current()
}

#[cfg(test)]
mod tests {
    use procfs_core::MemoryZoneType;

    use super::*;

    #[test]
    fn test_buddyinfo() {
        let info = buddyinfo().unwrap();
        assert!(info.iter().count() > 0);
        assert!(info.iter().any(|x| x.zone == MemoryZoneType::Normal));
    }
}
