use crate::{expect, build_internal_error, ProcResult, ProcError};

#[cfg(feature = "serde1")]
use serde::{Deserialize, Serialize};
use bitflags::bitflags;
use std::io;
use std::str::FromStr;
use std::convert::{TryFrom, TryInto};
use std::time::Duration;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
pub enum Persistency {
    MajorMinor(u8, u8),
    External(String),
    NonPersistent
}

impl Default for Persistency {
    fn default() -> Self {
        Persistency::MajorMinor(0, 90)
    }
}


#[derive(Debug, Clone, PartialOrd, PartialEq, Ord, Eq)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
pub struct DiskFlags(u8);

bitflags! {
    impl DiskFlags: u8 {
        const WriteMostly = 0b00000001;
        const Journal = 0b00000010;
        const Faulty = 0b00000100;
        const Spare = 0b00001000;
        const Replacement = 0b00010000;
        const InSync = 0b00100000;
    }
}

#[derive(Debug, Clone, PartialOrd, PartialEq, Ord, Eq)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
pub struct Disk {
    pub name: String,
    pub flags: DiskFlags
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
pub enum RwStatus {
    RW,
    AutoReadOnly,
    ReadOnly
}

impl Default for RwStatus {
    fn default() -> Self {
        Self::RW
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
pub struct PersonalityStatus {
    pub name: String,
    pub rw: RwStatus,
    pub level: Option<u8>,
    pub chunk_sectors: Option<u32>,
    pub algorithm: Option<u32>,
    pub degraded_disks: Option<u8>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
pub struct Bitmap {
    pub pages: usize,
    pub missing_pages: usize,
    pub pages_bytes: usize,
    pub chunk_bytes: usize
}

impl FromStr for Bitmap {
    type Err=ProcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split_whitespace();
        let bitmap = expect!(parts.next());
        if bitmap != "bitmap:" {
            return Err(build_internal_error!(format!("Expecting 'bitmap' got '{}'", bitmap)));
        }

        let mut pages_parts = expect!(parts.next()).split('/');
        let present_pages: usize = expect!(pages_parts.next()).parse()?;
        let pages = expect!(pages_parts.next()).parse()?;
        let missing_pages = pages - present_pages;

        let pagesstr = expect!(parts.next());
        if pagesstr != "pages" {
            return Err(build_internal_error!(format!("Expecting 'pages' got '{}'", pagesstr)));
        }

        let pkbs: usize = expect!(parts.next()).trim_start_matches('[').trim_end_matches("KB],").parse()?;

        let pages_bytes = pkbs * 1024;

        let cbytes = expect!(parts.next()).trim_end_matches('B');

        let (s, mul) = match cbytes.strip_suffix('K') {
            Some(s) => (s, 1024),
            None => (cbytes, 1)
        };

        let chunk_bytes = s.parse::<usize>()? * mul;

        Ok(Bitmap{pages, missing_pages, pages_bytes, chunk_bytes})
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
pub enum Recovery {
    Reshape,
    Check,
    Resync,
    Recover
}

impl FromStr for Recovery {
    type Err=ProcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "recover" | "recovery" => Ok(Recovery::Recover),
            "reshape" => Ok(Recovery::Reshape),
            "resync" => Ok(Recovery::Resync),
            "check" => Ok(Recovery::Check),
            _ => Err(build_internal_error!(format!("Expecting recovery flag, got '{}'", s)))
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
pub enum Resync {
    Remote(Recovery),
    Pending,
    Delayed,
    InProgress {
        recovery: Recovery,
        resync_sectors: u32,
        total_sectors: u32,
        recovery_permill: u16,
        estimated_duraion: Duration,
        bps: u64
    }
}

impl Resync {
    fn parse_in_progress<'a>(inp: &mut impl Iterator<Item=&'a str>) -> ProcResult<Self> {
        let recovery: Recovery = expect!(inp.next()).parse()?;
        expect!(inp.next());
        let mut permil_parts = expect!(inp.next()).trim_end_matches('%').split('.');
        let percent: u16 = expect!(permil_parts.next()).parse()?;
        let permill: u16 = expect!(permil_parts.next()).parse()?;
        let recovery_permill = 10 * percent + permill;

        let mut sector_parts = expect!(inp.next()).trim_start_matches('(').trim_end_matches(')').split('/');
        let resync_sectors = expect!(sector_parts.next()).parse()?;
        let total_sectors = expect!(sector_parts.next()).parse()?;

        let mut duration_parts = expect!(inp.next()).trim_start_matches("finish=").trim_end_matches("min").split('.');
        let minutes: u64 = expect!(duration_parts.next()).parse()?;
        let decimal_minutes: u64 = expect!(duration_parts.next()).parse()?;
        let estimated_duraion = Duration::from_secs(minutes * 60 + decimal_minutes * 6);

        let kbps: u64 = expect!(inp.next()).trim_start_matches("speed=").trim_end_matches("K/sec").parse()?;
        let bps = kbps * 1000;

        Ok(Resync::InProgress{recovery, resync_sectors, total_sectors, recovery_permill, estimated_duraion, bps})
    }
}

impl FromStr for Resync {
    type Err=ProcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split_whitespace();
        let p = expect!(parts.next(), "Expecting recovery info");
        match p {
            _ if p.ends_with("=REMOTE") => {
                Ok(Resync::Remote(expect!(p.split('=').next()).parse()?))
            }
            _ if p.ends_with("=PENDING") => Ok(Resync::Pending),
            _ if p.ends_with("=DELAYED") => Ok(Resync::Delayed),
            _ if p.trim_matches(&['[', ']', '=', '>', '.'] as &[_]).is_empty() => {
                Self::parse_in_progress(&mut parts)
            }
            _ => Err(build_internal_error!(format!("Expecting recovery info, got '{}'", p)))
        }

    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
pub struct MdDevice {
    pub name: String,
    pub personality: Option<PersonalityStatus>,
    pub disks: Vec<Disk>,
    pub persistent: Persistency,
    pub blocks: Option<u64>,
    pub bitmap: Option<Bitmap>,
    pub resync: Option<Resync>
}

enum Line1Parser {
    Name,
    Column,
    Active,
    RwOrRaid,
    RaidName,
    Disks,
}

impl Line1Parser {
    fn parse<'a>(&self, inp: &mut impl Iterator<Item=&'a str>, out: &mut Line1) -> ProcResult<()> {
        match self {
            Line1Parser::Name => {
                let name = expect!(inp.next(), "Missing device name.").trim();
                if name.is_empty() {
                    return Err(build_internal_error!("Missing device name."));
                }
                out.0 = Some(name.to_owned());
                Line1Parser::Column.parse(inp, out)
            },
            Line1Parser::Column => {
                let col = expect!(inp.next(), "Expecting ':' got end of the line.").trim();
                if col != ":" {
                    Err(build_internal_error!(format!("Expecting ':' got '{col}'.")))
                } else {
                    Line1Parser::Active.parse(inp, out)
                }
            },
            Line1Parser::Active => {
                let active = expect!(inp.next(), "Missing active flag.").trim();
                match active {
                    "active" => {
                        out.1 = true;
                        Line1Parser::RwOrRaid.parse(inp, out)
                    },
                    "inactive" => {
                        out.1 = false;
                        Line1Parser::Disks.parse(inp, out)
                    }
                    _ => Err(build_internal_error!(format!("Expecting '[in]active' got {active}")))
                }
            },
            Line1Parser::RwOrRaid => {
                let tok = expect!(inp.next(), "Missing personality name.").trim();
                match tok {
                    "(read-only)" => {
                        out.2 = Some(RwStatus::ReadOnly);
                        Line1Parser::RaidName.parse(inp, out)
                    },
                    "(auto-read-only)" => {
                        out.2 = Some(RwStatus::AutoReadOnly);
                        Line1Parser::RaidName.parse(inp, out)
                    },
                    _ if tok.chars().all(char::is_alphanumeric) => {
                        out.2 = Some(RwStatus::RW);
                        out.3 = Some(tok.to_owned());
                        Line1Parser::Disks.parse(inp, out)
                    },
                    _ => Err(build_internal_error!(format!("Expected personality name, got {}", tok)))
                }
            },
            Line1Parser::RaidName => {
                let name = expect!(inp.next(), "Missing personality name.").trim();
                out.3 = Some(name.to_owned());
                Line1Parser::Disks.parse(inp, out)
            },
            Line1Parser::Disks => {
                let mut disks = Vec::with_capacity(inp.size_hint().1.unwrap_or(16));
                for s in inp {
                    let mut toks = s.split_terminator(&['[', ']', '(', ')'] as &[_]);
                    let name = expect!(toks.next(), "Missing disk name.").trim().to_owned();
                    let ord = expect!(toks.next(), "Missing disk number.").trim();
                    let ordn: u8 = ord.parse()?;

                    let mut flags = DiskFlags::empty();
                    for t in toks {
                        match t {
                            "W" => flags.insert(DiskFlags::WriteMostly),
                            "J" => flags.insert(DiskFlags::Journal),
                            "F" => flags.insert(DiskFlags::Faulty),
                            "S" => flags.insert(DiskFlags::Spare),
                            "R" => flags.insert(DiskFlags::Replacement),
                            _ => return Err(build_internal_error!(format!("Unexpected disk flag {t}")))
                        }
                    }
                    disks.push((ordn, Disk{name, flags}));
                };
                disks.sort_unstable();
                out.4 = disks.into_iter().map(|(_, d)| d).collect();
                Ok(())
            },
        }
    }
}

#[derive(Default)]
struct Line1(Option<String>, bool, Option<RwStatus>, Option<String>, Vec<Disk>);

impl FromStr for Line1 {
    type Err=ProcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut ret = Line1::default();
        Line1Parser::Name.parse(&mut s.split_whitespace(), &mut ret)?;
        Ok(ret)
    }
}

enum Line2Parser {
    Blocks,
    Persistency,
    PersonalityKV,
    PersonalityDegraded
}

impl Line2Parser {
    fn parse<'a>(&self, inp: &mut impl Iterator<Item=&'a str>, peek: Option<&'a str>, out: &mut Line2) -> ProcResult<()> {
        match self {
            Line2Parser::Blocks => {
                let s = expect!(inp.next(), "Missing block count.");
                out.0 = Some(s.parse()?);
                let blocks = expect!(inp.next());
                if blocks != "blocks" {
                    return Err(build_internal_error!(format!("Expecting 'blocks' got '{}'", blocks)));
                }
                Line2Parser::Persistency.parse(inp, None, out)
            },
            Line2Parser::Persistency => {
                out.1 = Some(Persistency::default());
                match inp.next() {
                    Some("super") => {
                        let pt = expect!(inp.next(), "Missing persistence type.");
                        match pt {
                            "non-persistent" => out.1 = Some(Persistency::NonPersistent),
                            s if s.contains('.') => {
                                let mut parts = s.split('.');
                                let major: u8 = expect!(parts.next(), "Expecting device major version").parse()?;
                                let minor: u8 = expect!(parts.next(), "Expecting device minor version").parse()?;
                                out.1 = Some(Persistency::MajorMinor(major, minor))
                            },
                            s if s.contains(':') => {
                                let mut parts = s.split(':');
                                let external = expect!(parts.next(), "Expecting external persistency type");
                                if external != "external" {
                                    return Err(build_internal_error!(format!("Expected 'external' got '{}'", external)));
                                }
                                let etype = expect!(parts.next(), "Expecting external persistency type");
                                out.1 = Some(Persistency::External(etype.to_owned()));
                            },
                            _ => return Err(build_internal_error!(format!("Expected persistance type got {}", pt)))
                        }
                        Line2Parser::PersonalityKV.parse(inp, None, out)
                    },
                    Some(p) => Line2Parser::PersonalityKV.parse(inp, Some(p), out),
                    None => Ok(())
                }
            },
            Line2Parser::PersonalityKV => {
                let peek = peek.or_else(|| inp.next());
                if let Some(p) = peek {
                    match p {
                        "level" => {
                            out.2 = Some(expect!(inp.next(), "Expecting raid level.").trim_end_matches(',').parse()?);
                            self.parse(inp, None, out)
                        },
                        _ if p.ends_with('k') && p[..p.len() - 1].chars().all(char::is_numeric) => {
                            let chunk = expect!(inp.next(), "Expecting chunk").trim_end_matches(',');
                            if chunk != "chunk" {
                                Err(build_internal_error!(format!("Expected 'chunk', got '{}'", chunk)))
                            } else {
                                out.3 = Some(p[..p.len() - 1].parse()?);
                                self.parse(inp, None, out)
                            }
                        },
                        "algorithm" => {
                            out.4 = Some(
                                expect!(inp.next(), "Expecting algorithm type."
                            ).trim_end_matches(',').parse()?);
                            self.parse(inp, None, out)
                        }
                        _ if p.starts_with('[') => Line2Parser::PersonalityDegraded.parse(inp, Some(p), out),
                        _ => Err(build_internal_error!(
                            format!("Expected personality status, got '{}'", p))
                        )
                    }
                } else {
                    Ok(())
                }
            },
            Line2Parser::PersonalityDegraded => {
                let peek = peek.or_else(|| inp.next());
                if let Some(p) = peek {
                    match p.trim_matches(&['[', ']'] as &[_]) {
                        s if s.contains('/') => {
                            let mut deg = s.split('/');
                            let total: u8 = expect!(deg.next()).parse()?;
                            let ok: u8 = expect!(deg.next()).parse()?;
                            out.5 = Some(total - ok);
                            self.parse(inp, None, out)
                        }
                        s if s.chars().all(|c| "U_".contains(c)) => {
                            out.6.extend(s.chars().map(
                                |c| if c == 'U' {
                                    DiskFlags::InSync
                                } else {
                                    DiskFlags::empty()
                                }));
                            self.parse(inp, None, out)
                        }
                        _ => Err(build_internal_error!(format!("Expected disk health info got '{}'", p)))
                    }
                } else {
                    Ok(())
                }
            },
        }
    }
}

#[derive(Default)]
struct Line2(Option<u64>, Option<Persistency>, Option<u8>, Option<u32>, Option<u32>, Option<u8>, Vec<DiskFlags>);

impl FromStr for Line2 {
    type Err=ProcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut ret = Line2::default();
        Line2Parser::Blocks.parse(&mut s.trim().split_whitespace().peekable(), None, &mut ret)?;
        Ok(ret)
    }
}

impl TryFrom<&[String]> for MdDevice {
    type Error = ProcError;

    fn try_from(value: &[String]) -> Result<Self, Self::Error> {
        let mut ret = MdDevice{
            name: "".to_string(),
            personality: None,
            disks: vec![],
            persistent: Persistency::default(),
            blocks: None,
            bitmap: None,
            resync: None
        };

        let mut it = value.iter();
        let s1 = expect!(it.next(), "Expected device status");
        let mut l1: Line1 = s1.parse()?;
        ret.name = l1.0.take().unwrap();
        ret.disks.extend(l1.4.drain(..));

        let s2 = it.next();
        if l1.1 || !ret.disks.is_empty() {
            let mut l2: Line2 = expect!(s2, "Expected personality status.").trim().parse()?;
            ret.blocks = l2.0;
            ret.persistent = l2.1.unwrap();
            if l1.1 {
                ret.personality = Some(PersonalityStatus{
                    name: l1.3.unwrap(),
                    rw: l1.2.unwrap(),
                    level: l2.2,
                    chunk_sectors: l2.3.take(),
                    algorithm: l2.4.take(),
                    degraded_disks: l2.5
                });
                for (i, f) in l2.6.drain(..).enumerate() {
                    ret.disks[i].flags.insert(f);
                }
            }
        }

        let l3 = it.next();

        if let Some(l) = l3 {
            let resync: ProcResult<Resync> = l.trim().parse();
            match resync {
                Ok(r) => {
                    ret.resync = Some(r);
                    if let Some(l4) = it.next() {
                        ret.bitmap = Some(l4.parse()?)
                    }
                },
                Err(_) => ret.bitmap = Some(l.trim().parse()?)
            }
        }

        if let Some(l) = it.next() {
            Err(build_internal_error!(format!("Don't know how to parse line: '{}'", l)))
        } else {
            Ok(ret)
        }

    }
}

/// Represents the data from `/proc/mdstat`.
///
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
pub struct MdStat {
    pub personalities: Vec<String>,
    pub devices: Vec<MdDevice>,
    pub unused: Vec<String>
}

impl crate::FromBufRead for MdStat {

    fn from_buf_read<R: io::BufRead>(r: R) -> ProcResult<Self> {

        let mut personalities = vec![];
        let mut devices = vec![];
        let mut unused = vec![];

        let mut device_lines = vec![];

        for line in r.lines() {
            let line = line?;

            if line.trim().is_empty() {
                if !device_lines.is_empty() {
                    devices.push(device_lines.as_slice().try_into()?);
                    device_lines = vec![];
                }
                continue;
            }

            if line.starts_with("Personalities : ") {
                for word in line.split_whitespace().skip(2) {
                    let word = word.trim_matches(&['[', ']'] as &[_]);
                    personalities.push(word.parse()?);
                }
            } else if line.starts_with("unused devices: ") {
                for word in line.split_whitespace().skip(2) {
                    if word == "<none>" {
                        break;
                    }
                    unused.push(word.to_owned());
                }
            } else {
                device_lines.push(line);
            }

        }

        Ok(MdStat{personalities, devices, unused})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mdstat() {
        let data = r#"Personalities : [raid1] [raid6] [raid5] [raid4]
md1 : active raid1 sdb2[1] sda2[0]
      136448 blocks [2/2] [UU]

md127 : active raid5 sdh1[6] sdg1[4] sdf1[3] sde1[2] sdd1[1] sdc1[0]
      1464725760 blocks level 5, 64k chunk, algorithm 2 [6/5] [UUUUU_]
      [==>..................]  recovery = 12.6% (37043392/292945152) finish=127.5min speed=33440K/sec

md3 : active raid5 sdl1[9] sdk1[8] sdj1[7] sdi1[6] sdh1[5] sdg1[4] sdf1[3] sde1[2] sdd1[1] sdc1[0]
      1318680576 blocks level 5, 1024k chunk, algorithm 2 [10/10] [UUUUUUUUUU]

md_d0 : active raid5 sde1[0] sdf1[4] sdb1[5] sdd1[2] sdc1[1]
      1250241792 blocks super 1.2 level 5, 64k chunk, algorithm 2 [5/5] [UUUUU]
      bitmap: 0/10 pages [0KB], 16384KB chunk

unused devices: <none> "#;

        let r = std::io::Cursor::new(data.as_bytes());

        use crate::FromRead;

        let stat = MdStat::from_read(r).unwrap();
        assert_eq!(stat.personalities, vec!["raid1", "raid6", "raid5", "raid4"]);
        assert!(stat.unused.is_empty());
        assert_eq!(stat.devices.len(), 4);
        assert!(stat.devices[1].resync.is_some());
        assert!(stat.devices[3].bitmap.is_some());
    }

}
