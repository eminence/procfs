use super::MemoryMaps;
use crate::ProcResult;
use std::io::Read;

#[derive(Debug)]
pub struct SmapsRollup {
    pub memory_map_rollup: MemoryMaps,
}

impl SmapsRollup {
    pub fn from_reader<R: Read>(r: R) -> ProcResult<SmapsRollup> {
        MemoryMaps::from_reader(r).map(|m| SmapsRollup { memory_map_rollup: m })
    }
}
