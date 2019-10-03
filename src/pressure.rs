//! Pressure stall information retreived from `/proc/pressure/cpu`,
//! `/proc/pressure/memory` and `/proc/pressure/io`
//! might not be available on kernels older than 4.20.0
//! For reference: https://lwn.net/Articles/759781/
use crate::{ProcResult, ProcError};
use std::collections::HashMap;

#[derive(Debug)]
pub struct PressureRecord {
    avg10: f32,
    avg60: f32,
    avg300: f32,
    total: u64,
}

#[derive(Debug)]
pub struct CpuPressure {
    some: PressureRecord,
}

#[derive(Debug)]
pub struct MemoryPressure {
    some: PressureRecord,
    full: PressureRecord,
}

#[derive(Debug)]
pub struct IoPressure {
    some: PressureRecord,
    full: PressureRecord,
}

fn get_f32(map: &HashMap<&str, &str>, value: &str) -> ProcResult<f32> {
    map.get(value)
       .map_or_else(|| Err(ProcError::Incomplete(None)),
                    |v| Ok(v.parse::<f32>()
                            .map_err(|_| ProcError::Incomplete(None))?)
       )
}

fn get_total(map: &HashMap<&str, &str>) -> ProcResult<u64> {
    map.get("total")
       .map_or_else(|| Err(ProcError::Incomplete(None)),
                    |v| Ok(v.parse::<u64>()
                            .map_err(|_| ProcError::Incomplete(None))?)
       )
}

fn parse_pressure_record(line: &str) -> ProcResult<PressureRecord> {
    let mut parsed = HashMap::new();

    if !line.starts_with("some") && !line.starts_with("full") {
        return Err(ProcError::Incomplete(None));
    }

    let values = &line[5..];

    for kv_str in values.split_whitespace() {
        let kv_split = kv_str.split('=');
        let vec: Vec<&str> = kv_split.collect();
        if vec.len() == 2 {
            parsed.insert(vec[0], vec[1]);
        }
    }

    Ok(PressureRecord {
        avg10: get_f32(&parsed, "avg10")?,
        avg60: get_f32(&parsed, "avg60")?,
        avg300: get_f32(&parsed, "avg300")?,
        total: get_total(&parsed)?,
    })

}

pub fn cpu_pressure() -> ProcResult<CpuPressure> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open("/proc/pressure/cpu")?;
    let mut reader = BufReader::new(file);

    let mut some = String::new();
    reader.read_line(&mut some)?;

    Ok(CpuPressure {
        some: parse_pressure_record(&some)?,
    })
}

fn get_pressure(pressure_file: &str) -> ProcResult<(PressureRecord, PressureRecord)> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open(format!("/proc/pressure/{}", pressure_file))?;
    let mut reader = BufReader::new(file);

    let mut some = String::new();
    reader.read_line(&mut some)?;
    let mut full = String::new();
    reader.read_line(&mut full)?;


    Ok((parse_pressure_record(&some)?, parse_pressure_record(&full)?))
}

pub fn memory_pressure() -> ProcResult<MemoryPressure> {
    let (some, full) = get_pressure("memory")?;

    Ok(MemoryPressure { some, full })
}

pub fn io_pressure() -> ProcResult<MemoryPressure> {
    let (some, full) = get_pressure("io")?;

    Ok(MemoryPressure { some, full })
}

#[cfg(test)]
mod test {
    use super::*;
    use std::f32::EPSILON;

    #[test]
    fn test_parse_pressure_record() {
        let record =
            parse_pressure_record("full avg10=2.10 avg60=0.12 avg300=0.00 total=391926")
            .unwrap();

        assert!(record.avg10 - 2.10 < EPSILON);
        assert!(record.avg60 - 0.12 < EPSILON);
        assert!(record.avg300 - 0.00 < EPSILON);
        assert_eq!(record.total, 391_926);
    }

    #[test]
    fn test_parse_pressure_record_errs() {
        assert!(parse_pressure_record("avg10=2.10 avg60=0.12 avg300=0.00 total=391926")
                .is_err());
        assert!(parse_pressure_record("some avg10=2.10 avg300=0.00 total=391926")
                .is_err());
        assert!(parse_pressure_record("some avg10=2.10 avg60=0.00 avg300=0.00")
                .is_err());
    }
}
