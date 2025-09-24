use std::str::FromStr;
use std::{collections::HashMap, fmt::Display, ops::Add};

#[cfg(feature = "serde1")]
use serde::{Deserialize, Serialize};

use crate::{Pages, ProcError};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
/// Free memory fragmentation data for a specific NUMA node and memory zone.
pub struct BuddyInfoEntry {
    /// The NUMA node
    pub node: u8,

    /// The memory zone
    pub zone: MemoryZoneType,

    /// A map of chunk size (in number of pages) to free chunk count
    free_chunks: HashMap<Pages, u64>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
/// Free memory fragmentation data for the entire system.
///
/// Contains one entry per unique (NUMA node, memory zone) on the system.
pub struct BuddyInfo {
    /// The complete set of entries
    entries: Vec<BuddyInfoEntry>,
}

/// Kernel memory zone types.
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MemoryZoneType {
    DMA = 1,
    DMA32 = 2,
    Normal = 3,
    HighMem = 4,
    Movable = 5,
    Device = 6,
}

impl FromStr for MemoryZoneType {
    type Err = ProcError;

    fn from_str(value: &str) -> Result<MemoryZoneType, Self::Err> {
        match value {
            "DMA" => Ok(MemoryZoneType::DMA),
            "DMA32" => Ok(MemoryZoneType::DMA32),
            "Normal" => Ok(MemoryZoneType::Normal),
            "HighMem" => Ok(MemoryZoneType::HighMem),
            "Movable" => Ok(MemoryZoneType::Movable),
            "Device" => Ok(MemoryZoneType::Device),
            _ => Err(ProcError::Other(format!("{} is not a valid zone type", value))),
        }
    }
}

impl Display for MemoryZoneType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryZoneType::DMA => write!(f, "DMA"),
            MemoryZoneType::DMA32 => write!(f, "DMA32"),
            MemoryZoneType::Normal => write!(f, "Normal"),
            MemoryZoneType::HighMem => write!(f, "HighMem"),
            MemoryZoneType::Movable => write!(f, "Movable"),
            MemoryZoneType::Device => write!(f, "Device"),
        }
    }
}

impl crate::FromBufRead for BuddyInfo {
    fn from_buf_read<R: std::io::BufRead>(r: R) -> crate::ProcResult<Self> {
        let mut entries = Vec::new();

        for line in r.lines().flatten() {
            if !line.is_empty() {
                let mut s = line.split_whitespace();

                // Skip "Node" literal
                s.next();

                let node_id_str = expect!(s.next()).trim_end_matches(',');

                let node = from_str!(u8, node_id_str);

                // Skip "zone" literal
                s.next();

                let zone = MemoryZoneType::from_str(expect!(s.next()))?;

                let page_sizes = (0u64..).map(|x| 1 << x);

                let mut free_chunks = HashMap::new();
                for (size, count) in page_sizes.zip(s) {
                    let count = from_str!(u64, count);
                    free_chunks.insert(Pages(size), count);
                }

                entries.push(BuddyInfoEntry {
                    node,
                    zone,
                    free_chunks,
                });
            }
        }

        Ok(BuddyInfo { entries })
    }
}

impl BuddyInfo {
    /// Get the entry for a specific NUMA node and memory zone
    pub fn get(&self, numa_node: u8, zone: MemoryZoneType) -> Option<&BuddyInfoEntry> {
        self.entries.iter().find(|x| x.node == numa_node && x.zone == zone)
    }

    /// Get all entries on the given NUMA node
    pub fn on_node(&self, numa_node: u8) -> impl Iterator<Item = &BuddyInfoEntry> + use<'_> {
        self.entries.iter().filter(move |x| x.node == numa_node)
    }

    /// Get all entries in the given memory zone
    pub fn in_zone(&self, zone: MemoryZoneType) -> impl Iterator<Item = &BuddyInfoEntry> + use<'_> {
        self.entries.iter().filter(move |x| x.zone == zone)
    }

    /// Get an iterator over the entries in this BuddyInfo
    pub fn iter(&self) -> impl Iterator<Item = &BuddyInfoEntry> + use<'_> {
        self.entries.iter()
    }
}

/// Implement into_iter() for the underlying Vec of entries
impl IntoIterator for BuddyInfo {
    type Item = <Vec<BuddyInfoEntry> as IntoIterator>::Item;
    type IntoIter = <Vec<BuddyInfoEntry> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug)]
pub struct BuddyInfoItem {
    pub npages: Pages,
    pub nchunks: u64,
}

impl BuddyInfoEntry {
    /// Get the total number of free pages across all nodes and zones
    pub fn total_free(&self) -> Pages {
        self.filtered(|_| true)
    }

    /// Get the number of free pages available in chunks of exactly `npages`` pages
    pub fn free_in_chunks_of(&self, npages: u64) -> Pages {
        self.filtered(|c| c == npages.into())
    }

    /// Get the total number of free pages available in chunks of at least `npages`` pages
    pub fn free_in_chunks_gteq(&self, npages: u64) -> Pages {
        self.filtered(|c| c >= npages.into())
    }

    /// Get the total number of free pages available in chunks of less than `npages`` pages
    pub fn free_in_chunks_lt(&self, npages: u64) -> Pages {
        self.filtered(|c| c < npages.into())
    }

    /// Iterate over available (number of pages in chunk, number of chunks) items
    pub fn iter(&self) -> impl Iterator<Item = BuddyInfoItem> + use<'_> {
        self.free_chunks.iter().map(|x| BuddyInfoItem {
            npages: *x.0,
            nchunks: *x.1,
        })
    }

    fn filtered<F>(&self, op: F) -> Pages
    where
        F: Fn(Pages) -> bool,
    {
        self.free_chunks
            .iter()
            .filter(|x| op(*x.0))
            .map(|x| *x.0 * *x.1)
            .reduce(Pages::add)
            .unwrap_or(0.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buddyinfo_parsing() {
        let data = r#"Node 0, zone      DMA      0      0      0      0      0      0      0      0      1      1      2
Node 0, zone    DMA32      3      2      1      1      1      2      2      2      3      3    480
Node 0, zone   Normal   2778    421   1223  21849   8276   3067    458     91     43     38  25537
Node 1, zone   Normal  18848   6919  20881  10325   5615   2880    936    393    102     20  27681"#;

        let r = std::io::Cursor::new(data.as_bytes());

        use crate::FromRead;

        let info = BuddyInfo::from_read(r).unwrap();

        assert_eq!(info.entries.len(), 4);
        let entry = info.get(0, MemoryZoneType::Normal);
        assert!(entry.is_some());
        let entry = entry.unwrap();

        assert_eq!(entry.free_in_chunks_of(32), (3067 * 1 << 5).into());

        let pages_greater_than_2mb = entry.free_in_chunks_gteq(1 << 9);
        assert_eq!(pages_greater_than_2mb, ((38 * 1 << 9) + (25537 * 1 << 10)).into());

        let pages_smaller_than_2mb = entry.free_in_chunks_lt(1 << 9);
        assert_eq!(
            pages_smaller_than_2mb,
            (2778
                + (421 * 2)
                + (1223 * 1 << 2)
                + (21849 * 1 << 3)
                + (8276 * 1 << 4)
                + (3067 * 1 << 5)
                + (458 * 1 << 6)
                + (91 * 1 << 7)
                + (43 * 1 << 8))
                .into()
        );

        // Test some helpers
        assert_eq!(info.on_node(1).count(), 1);
        assert_eq!(info.on_node(32).count(), 0);
        assert_eq!(info.in_zone(MemoryZoneType::DMA).count(), 1);
        assert_eq!(info.in_zone(MemoryZoneType::Movable).count(), 0);
    }
}
