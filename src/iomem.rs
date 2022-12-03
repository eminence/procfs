#[cfg(feature = "serde1")]
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader};

use super::{FileWrapper, ProcResult};
use crate::split_into_num;

/// Reads and parses the `/proc/iomem`, returning an error if there are problems.
///
/// Requires root, otherwise every memory address will be zero
pub fn iomem() -> ProcResult<Vec<PhysicalMemoryMap>> {
    let f = FileWrapper::open("/proc/iomem")?;

    let reader = BufReader::new(f);
    let mut vec = Vec::new();

    for line in reader.lines() {
        let line = expect!(line);

        let map = PhysicalMemoryMap::from_line(&line)?;

        vec.push(map);
    }

    Ok(vec)
}

/// To construct this structure, see [crate::IoMem::new].
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
pub struct PhysicalMemoryMap {
    /// The address space in the process that the mapping occupies.
    pub address: (u64, u64),
    pub name: String,
}

impl PhysicalMemoryMap {
    fn from_line(line: &str) -> ProcResult<PhysicalMemoryMap> {
        let line = line.trim();
        let mut s = line.split(" : ");
        let address = expect!(s.next());
        let name = expect!(s.next());

        Ok(PhysicalMemoryMap {
            address: split_into_num(address, '-', 16)?,
            name: String::from(name),
        })
    }
}
