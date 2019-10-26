//! Information about the networking layer.
//!
//! This module corresponds to the `/proc/net` directory and contains various information about the
//! networking layer.
//!
//! # Example
//!
//! Here's an example that will print out all of the open and listening TCP sockets, and their
//! corresponding processes, if know.  This mimics the "netstat" utility, but for TCP only.  You
//! can run this example yourself with:
//!
//! > cargo run --example=netstat
//!
//! ```rust
//! # use procfs::process::{Process, FDTarget};
//! # use std::collections::HashMap;
//! let all_procs = procfs::process::all_processes().unwrap();
//!
//! // build up a map between socket inodes and processes:
//! let mut map: HashMap<u32, &Process> = HashMap::new();
//! for process in &all_procs {
//!     if let Ok(fds) = process.fd() {
//!         for fd in fds {
//!             if let FDTarget::Socket(inode) = fd.target {
//!                 map.insert(inode, process);
//!             }
//!         }
//!     }
//! }
//!
//! // get the tcp table
//! let tcp = procfs::net::tcp().unwrap();
//! let tcp6 = procfs::tcp6().unwrap();
//! println!("{:<26} {:<26} {:<15} {:<8} {}", "Local address", "Remote address", "State", "Inode", "PID/Program name");
//! for entry in tcp.into_iter().chain(tcp6) {
//!     // find the process (if any) that has an open FD to this entry's inode
//!     let local_address = format!("{}", entry.local_address);
//!     let remote_addr = format!("{}", entry.remote_address);
//!     let state = format!("{:?}", entry.state);
//!     if let Some(process) = map.get(&entry.inode) {
//!         println!("{:<26} {:<26} {:<15} {:<8} {}/{}", local_address, remote_addr, state, entry.inode, process.stat.pid, process.stat.comm);
//!     } else {
//!         // We might not always be able to find the process assocated with this socket
//!         println!("{:<26} {:<26} {:<15} {:<8} -", local_address, remote_addr, state, entry.inode);
//!     }
//! }
use crate::ProcResult;

use crate::FileWrapper;
use byteorder::{ByteOrder, NetworkEndian};
use hex;
use std::io::{BufRead, BufReader, Read};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

#[derive(Debug, PartialEq)]
pub enum TcpState {
    Established = 1,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    NewSynRecv,
}

impl TcpState {
    pub fn from_u8(num: u8) -> Option<TcpState> {
        match num {
            0x01 => Some(TcpState::Established),
            0x02 => Some(TcpState::SynSent),
            0x03 => Some(TcpState::SynRecv),
            0x04 => Some(TcpState::FinWait1),
            0x05 => Some(TcpState::FinWait2),
            0x06 => Some(TcpState::TimeWait),
            0x07 => Some(TcpState::Close),
            0x08 => Some(TcpState::CloseWait),
            0x09 => Some(TcpState::LastAck),
            0x0A => Some(TcpState::Listen),
            0x0B => Some(TcpState::Closing),
            0x0C => Some(TcpState::NewSynRecv),
            _ => None,
        }
    }
}

/// An entry in the TCP socket table
#[derive(Debug)]
pub struct TcpNetEntry {
    pub local_address: SocketAddr,
    pub remote_address: SocketAddr,
    pub state: TcpState,
    pub rx_queue: u32,
    pub tx_queue: u32,
    pub inode: u32,
}

/// An entry in the UDP socket table
#[derive(Debug)]
pub struct UdpNetEntry {
    pub local_address: SocketAddr,
    pub remote_address: SocketAddr,
    pub rx_queue: u32,
    pub tx_queue: u32,
    pub inode: u32,
}

/// Parses an address in the form 00010203:1234
///
/// Also supports IPv6
fn parse_addressport_str(s: &str) -> ProcResult<SocketAddr> {
    let mut las = s.split(':');
    let ip_part = expect!(las.next(), "ip_part");
    let port = expect!(las.next(), "port");
    let port = from_str!(u16, port, 16);

    if ip_part.len() == 8 {
        let bytes = expect!(hex::decode(&ip_part));
        let ip_u32 = NetworkEndian::read_u32(&bytes);

        let ip = Ipv4Addr::new(
            (ip_u32 & 0xff) as u8,
            ((ip_u32 & 0xff << 8) >> 8) as u8,
            ((ip_u32 & 0xff << 16) >> 16) as u8,
            ((ip_u32 & 0xff << 24) >> 24) as u8,
        );

        Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    } else if ip_part.len() == 32 {
        let bytes = expect!(hex::decode(&ip_part));
        let ip_u128 = NetworkEndian::read_u128(&bytes);

        let ip = Ipv6Addr::new(
            (ip_u128 & 0xffff) as u16,
            ((ip_u128 & 0xffff << 16) >> 16) as u16,
            ((ip_u128 & 0xffff << 32) >> 32) as u16,
            ((ip_u128 & 0xffff << 48) >> 48) as u16,
            ((ip_u128 & 0xffff << 64) >> 64) as u16,
            ((ip_u128 & 0xffff << 80) >> 80) as u16,
            ((ip_u128 & 0xffff << 96) >> 96) as u16,
            ((ip_u128 & 0xffff << 112) >> 112) as u16,
        );

        Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
    } else {
        Err(build_internal_error!(format!(
            "Unable to parse {:?} as an address:port",
            s
        )))
    }
}

fn read_tcp_table<R: Read>(reader: BufReader<R>) -> ProcResult<Vec<TcpNetEntry>> {
    let mut vec = Vec::new();

    // first line is a header we need to skip
    for line in reader.lines().skip(1) {
        let line = line?;
        let mut s = line.split_whitespace();
        s.next();
        let local_address = expect!(s.next(), "tcp::local_address");
        let rem_address = expect!(s.next(), "tcp::rem_address");
        let state = expect!(s.next(), "tcp::st");
        let mut tx_rx_queue = expect!(s.next(), "tcp::tx_queue:rx_queue").splitn(2, ':');
        let tx_queue = from_str!(u32, expect!(tx_rx_queue.next(), "tcp::tx_queue"), 16);
        let rx_queue = from_str!(u32, expect!(tx_rx_queue.next(), "tcp::rx_queue"), 16);
        s.next(); // skip tr and tm->when
        s.next(); // skip retrnsmt
        s.next(); // skip uid
        s.next(); // skip timeout
        let inode = expect!(s.next(), "tcp::inode");

        vec.push(TcpNetEntry {
            local_address: parse_addressport_str(local_address)?,
            remote_address: parse_addressport_str(rem_address)?,
            rx_queue,
            tx_queue,
            state: expect!(TcpState::from_u8(from_str!(u8, state, 16))),
            inode: from_str!(u32, inode),
        });
    }

    Ok(vec)
}

fn read_udp_table<R: Read>(reader: BufReader<R>) -> ProcResult<Vec<UdpNetEntry>> {
    let mut vec = Vec::new();

    // first line is a header we need to skip
    for line in reader.lines().skip(1) {
        let line = line?;
        let mut s = line.split_whitespace();
        s.next();
        let local_address = expect!(s.next(), "udp::local_address");
        let rem_address = expect!(s.next(), "udp::rem_address");
        s.next(); // skip state
        let mut tx_rx_queue = expect!(s.next(), "udp::tx_queue:rx_queue").splitn(2, ':');
        let tx_queue: u32 = from_str!(u32, expect!(tx_rx_queue.next(), "udp::tx_queue"), 16);
        let rx_queue: u32 = from_str!(u32, expect!(tx_rx_queue.next(), "udp::rx_queue"), 16);
        s.next(); // skip tr and tm->when
        s.next(); // skip retrnsmt
        s.next(); // skip uid
        s.next(); // skip timeout
        let inode = expect!(s.next(), "udp::inode");

        vec.push(UdpNetEntry {
            local_address: parse_addressport_str(local_address)?,
            remote_address: parse_addressport_str(rem_address)?,
            rx_queue,
            tx_queue,
            inode: from_str!(u32, inode),
        });
    }

    Ok(vec)
}

/// Reads the tcp socket table
pub fn tcp() -> ProcResult<Vec<TcpNetEntry>> {
    let file = FileWrapper::open("/proc/net/tcp")?;

    read_tcp_table(BufReader::new(file))
}

/// Reads the tcp6 socket table
pub fn tcp6() -> ProcResult<Vec<TcpNetEntry>> {
    let file = FileWrapper::open("/proc/net/tcp6")?;

    read_tcp_table(BufReader::new(file))
}

/// Reads the udp socket table
pub fn udp() -> ProcResult<Vec<UdpNetEntry>> {
    let file = FileWrapper::open("/proc/net/udp")?;

    read_udp_table(BufReader::new(file))
}

/// Reads the udp6 socket table
pub fn udp6() -> ProcResult<Vec<UdpNetEntry>> {
    let file = FileWrapper::open("/proc/net/udp6")?;

    read_udp_table(BufReader::new(file))
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_parse_ipaddr() {
        use std::str::FromStr;

        let addr = parse_addressport_str("0100007F:1234").unwrap();
        assert_eq!(addr.port(), 0x1234);
        match addr.ip() {
            IpAddr::V4(addr) => assert_eq!(addr, Ipv4Addr::new(127, 0, 0, 1)),
            _ => panic!("Not IPv4"),
        }

        let addr = parse_addressport_str("5014002A18080140000000000E200000:0050").unwrap();
        assert_eq!(addr.port(), 80);
        match addr.ip() {
            IpAddr::V6(addr) => {
                assert_eq!(addr, Ipv6Addr::from_str("0:e20::140:1808:2a:5014").unwrap())
            }
            _ => panic!("Not IPv6"),
        }

        let addr = parse_addressport_str("1234:1234");
        assert!(addr.is_err());

        // tcp6       0      0 2a01:4f8:110:31e8:33141 2a00:1450:4001:818:::80 TIME_WAIT
        //   11: F804012AE83110010000000002000000:8175 5014002A18080140000000000E200000:0050 06 00000000:00000000 03:00001237 00000000     0        0 0 3 ffff88070a777340
        //   0:e20::140:1808:2a:5014
    }

    #[test]
    fn test_tcpstate_from() {
        assert_eq!(TcpState::from_u8(0xA).unwrap(), TcpState::Listen);
    }

    #[test]
    fn test_tcp() {
        for entry in tcp().unwrap() {
            println!("{:?}", entry);
        }
    }

    #[test]
    fn test_tcp6() {
        for entry in tcp6().unwrap() {
            println!("{:?}", entry);
        }
    }

    #[test]
    fn test_udp() {
        for entry in udp().unwrap() {
            println!("{:?}", entry);
        }
    }

    #[test]
    fn test_udp6() {
        for entry in udp6().unwrap() {
            println!("{:?}", entry);
        }
    }
}
