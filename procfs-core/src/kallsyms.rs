use std::io::BufRead;
use std::str::FromStr;

use crate::{FromBufRead, ProcError, ProcResult};

#[cfg(feature = "serde1")]
use serde::{Deserialize, Serialize};

/// KAllSyms entries under `/proc/kallsyms`
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
pub struct KAllSyms {
    /// Kernel symbols
    pub symbols: Vec<KAllSymsEntry>,
}

/// A kernel symbol entry under `/proc/kallsyms`
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
pub struct KAllSymsEntry {
    /// Address of the symbol
    pub address: u64,
    /// Symbol type
    pub symbol_type: char,
    /// Symbol name
    pub name: String,
    /// Optional module name
    pub module_name: Option<String>,
}

impl FromBufRead for KAllSyms {
    fn from_buf_read<R: BufRead>(r: R) -> ProcResult<Self> {
        let mut symbols = Vec::new();
        for line in r.lines() {
            let line = line?;
            let entry = KAllSymsEntry::from_str(&line)?;
            symbols.push(entry);
        }
        Ok(KAllSyms { symbols })
    }
}

impl std::str::FromStr for KAllSymsEntry {
    type Err = ProcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut it = s.splitn(3, ' ');
        let address = from_str!(u64, expect!(it.next()), 16);
        let symbol_type = expect!(it.next());

        let symbol_type = {
            if symbol_type.len() != 1 {
                return Err(ProcError::Other(format!(
                    "Invalid symbol type: {}, expected a single character",
                    symbol_type
                )));
            }
            symbol_type.chars().next().unwrap()
        };

        let mut it = expect!(it.next()).splitn(2, '\t');
        let name = expect!(it.next()).to_string();

        let module_name = if let Some(module_name) = it.next() {
            // Check [ and ] around module name
            if module_name.starts_with('[') && module_name.ends_with(']') {
                Some(module_name[1..module_name.len() - 1].to_string())
            } else {
                return Err(ProcError::Other(format!(
                    "Invalid module name format: {}, expected [module_name]",
                    module_name
                )));
            }
        } else {
            None
        };

        Ok(KAllSymsEntry {
            address,
            symbol_type,
            name,
            module_name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kallsymsentry() {
        let s = "c000000000000000 T _text";
        let entry = KAllSymsEntry::from_str(s).unwrap();
        assert_eq!(entry.address, 0xc000000000000000);
        assert_eq!(entry.symbol_type, 'T');
        assert_eq!(entry.name, "_text");
        assert!(entry.module_name.is_none());

        let s = "c000000000000000 T _text\t[module_name]";
        let entry = KAllSymsEntry::from_str(s).unwrap();
        assert_eq!(entry.address, 0xc000000000000000);
        assert_eq!(entry.symbol_type, 'T');
        assert_eq!(entry.name, "_text");
        assert_eq!(entry.module_name.unwrap(), "module_name");
    }

    #[test]
    fn test_kallsyms() {
        let data = "cb00000000000000 T _text
c000000000000000 T _start
c000000000000100 t bpf_text\t[bpf]
";
        let mut reader = std::io::Cursor::new(data);
        let kallsyms = KAllSyms::from_buf_read(&mut reader).unwrap();

        assert_eq!(kallsyms.symbols.len(), 3);
        assert_eq!(kallsyms.symbols[0].address, 0xcb00000000000000);
        assert_eq!(kallsyms.symbols[0].symbol_type, 'T');
        assert_eq!(kallsyms.symbols[0].name, "_text");
        assert!(kallsyms.symbols[0].module_name.is_none());

        assert_eq!(kallsyms.symbols[1].address, 0xc000000000000000);
        assert_eq!(kallsyms.symbols[1].symbol_type, 'T');
        assert_eq!(kallsyms.symbols[1].name, "_start");
        assert!(kallsyms.symbols[1].module_name.is_none());

        assert_eq!(kallsyms.symbols[2].address, 0xc000000000000100);
        assert_eq!(kallsyms.symbols[2].symbol_type, 't');
        assert_eq!(kallsyms.symbols[2].name, "bpf_text");
        assert_eq!(kallsyms.symbols[2].module_name.as_ref().unwrap(), "bpf");
    }
}
