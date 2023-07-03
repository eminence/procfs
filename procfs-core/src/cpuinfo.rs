use crate::{expect, ProcResult};

#[cfg(feature = "serde1")]
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io::BufRead};

/// Represents the data from `/proc/cpuinfo`.
///
/// The `fields` field stores the fields that are common among all CPUs.  The `cpus` field stores
/// CPU-specific info.
///
/// For common fields, there are methods that will return the data, converted to a more appropriate
/// data type.  These methods will all return `None` if the field doesn't exist, or is in some
/// unexpected format (in that case, you'll have to access the string data directly).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
pub struct CpuInfo {
    /// This stores fields that are common among all CPUs
    pub fields: HashMap<String, String>,
    pub cpus: Vec<HashMap<String, String>>,
}

impl crate::FromBufRead for CpuInfo {
    fn from_buf_read<R: BufRead>(r: R) -> ProcResult<Self> {
        let mut list = Vec::new();
        let mut map = Some(HashMap::new());

        // the first line of a cpu block must start with "processor"
        let mut found_first = false;

        for line in r.lines().flatten() {
            if !line.is_empty() {
                let mut s = line.split(':');
                let key = expect!(s.next());
                if !found_first && key.trim() == "processor" {
                    found_first = true;
                }
                if !found_first {
                    continue;
                }
                if let Some(value) = s.next() {
                    let key = key.trim().to_owned();
                    let value = value.trim().to_owned();

                    map.get_or_insert(HashMap::new()).insert(key, value);
                }
            } else if let Some(map) = map.take() {
                list.push(map);
                found_first = false;
            }
        }
        if let Some(map) = map.take() {
            list.push(map);
        }

        // find properties that are the same for all cpus
        assert!(!list.is_empty());

        let common_fields: Vec<String> = list[0]
            .iter()
            .filter_map(|(key, val)| {
                if list.iter().all(|map| map.get(key).map_or(false, |v| v == val)) {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();

        let mut common_map = HashMap::new();
        for (k, v) in &list[0] {
            if common_fields.contains(k) {
                common_map.insert(k.clone(), v.clone());
            }
        }

        for map in &mut list {
            map.retain(|k, _| !common_fields.contains(k));
        }

        Ok(CpuInfo {
            fields: common_map,
            cpus: list,
        })
    }
}

impl CpuInfo {
    /// Get the total number of cpu cores.
    ///
    /// This is the number of entries in the `/proc/cpuinfo` file.
    pub fn num_cores(&self) -> usize {
        self.cpus.len()
    }

    /// Get info for a specific cpu.
    ///
    /// This will merge the common fields with the cpu-specific fields.
    ///
    /// Returns None if the requested cpu index is not found.
    pub fn get_info(&self, cpu_num: usize) -> Option<HashMap<&str, &str>> {
        self.cpus.get(cpu_num).map(|info| {
            self.fields
                .iter()
                .chain(info.iter())
                .map(|(k, v)| (k.as_ref(), v.as_ref()))
                .collect()
        })
    }

    /// Get the content of a specific field associated to a CPU
    ///
    /// Returns None if the requested cpu index is not found.
    pub fn get_field(&self, cpu_num: usize, field_name: &str) -> Option<&str> {
        self.cpus.get(cpu_num).and_then(|cpu_fields| {
            cpu_fields
                .get(field_name)
                .or_else(|| self.fields.get(field_name))
                .map(|s| s.as_ref())
        })
    }

    pub fn model_name(&self, cpu_num: usize) -> Option<&str> {
        self.get_field(cpu_num, "model name")
    }

    pub fn vendor_id(&self, cpu_num: usize) -> Option<&str> {
        self.get_field(cpu_num, "vendor_id")
    }

    /// May not be available on some older 2.6 kernels
    pub fn physical_id(&self, cpu_num: usize) -> Option<u32> {
        self.get_field(cpu_num, "physical id").and_then(|s| s.parse().ok())
    }

    pub fn flags(&self, cpu_num: usize) -> Option<Vec<&str>> {
        self.get_field(cpu_num, "flags")
            .map(|flags| flags.split_whitespace().collect())
    }
}

impl IntoIterator for CpuInfo {
    type Item = CpuCore;
    type IntoIter = CpuCoreIterator;

    fn into_iter(self) -> Self::IntoIter {
        CpuCoreIterator {
            cpu_info: self,
            cpu_num: 0,
        }
    }
}

#[derive(Debug)]
pub struct CpuCore {
    pub cpu_num: usize,
    pub model_name: Option<String>,
    pub vendor_id: Option<String>,
    pub physical_id: Option<u32>,
    pub flags: Vec<String>,
}

#[derive(Debug)]
pub struct CpuCoreIterator {
    cpu_info: CpuInfo,
    cpu_num: usize,
}

impl Iterator for CpuCoreIterator {
    type Item = CpuCore;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cpu_num < self.cpu_info.num_cores() {
            let core = CpuCore {
                cpu_num: self.cpu_num,
                model_name: self.cpu_info.model_name(self.cpu_num).map(ToString::to_string),
                vendor_id: self.cpu_info.vendor_id(self.cpu_num).map(ToString::to_string),
                physical_id: self.cpu_info.physical_id(self.cpu_num),
                flags: self
                    .cpu_info
                    .flags(self.cpu_num)
                    .map_or_else(Vec::default, |flags| flags.iter().map(ToString::to_string).collect()),
            };
            self.cpu_num += 1;
            Some(core)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpuinfo_rpi() {
        // My rpi system includes some stuff at the end of /proc/cpuinfo that we shouldn't parse
        let data = r#"processor       : 0
model name      : ARMv7 Processor rev 4 (v7l)
BogoMIPS        : 38.40
Features        : half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm crc32
CPU implementer : 0x41
CPU architecture: 7
CPU variant     : 0x0
CPU part        : 0xd03
CPU revision    : 4

processor       : 1
model name      : ARMv7 Processor rev 4 (v7l)
BogoMIPS        : 38.40
Features        : half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm crc32
CPU implementer : 0x41
CPU architecture: 7
CPU variant     : 0x0
CPU part        : 0xd03
CPU revision    : 4

processor       : 2
model name      : ARMv7 Processor rev 4 (v7l)
BogoMIPS        : 38.40
Features        : half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm crc32
CPU implementer : 0x41
CPU architecture: 7
CPU variant     : 0x0
CPU part        : 0xd03
CPU revision    : 4

processor       : 3
model name      : ARMv7 Processor rev 4 (v7l)
BogoMIPS        : 38.40
Features        : half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm crc32
CPU implementer : 0x41
CPU architecture: 7
CPU variant     : 0x0
CPU part        : 0xd03
CPU revision    : 4

Hardware        : BCM2835
Revision        : a020d3
Serial          : 0000000012345678
Model           : Raspberry Pi 3 Model B Plus Rev 1.3
"#;

        let r = std::io::Cursor::new(data.as_bytes());

        use crate::FromRead;

        let cpu_info = CpuInfo::from_read(r).unwrap();
        assert_eq!(cpu_info.num_cores(), 4);
        let info = cpu_info.get_info(0).unwrap();
        assert!(info.get("model name").is_some());
        assert!(info.get("BogoMIPS").is_some());
        assert!(info.get("Features").is_some());
        assert!(info.get("CPU implementer").is_some());
        assert!(info.get("CPU architecture").is_some());
        assert!(info.get("CPU variant").is_some());
        assert!(info.get("CPU part").is_some());
        assert!(info.get("CPU revision").is_some());

        (0..cpu_info.num_cores())
            .zip(cpu_info.clone())
            .for_each(|(core, view)| {
                assert_eq!(cpu_info.model_name(core), view.model_name.as_deref());
                assert_eq!(cpu_info.vendor_id(core), view.vendor_id.as_deref());
                assert_eq!(cpu_info.physical_id(core), view.physical_id);
                assert_eq!(
                    cpu_info.flags(core).unwrap_or_default(),
                    view.flags.iter().map(String::as_str).collect::<Vec<_>>()
                );
            });
    }
}
