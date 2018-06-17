use ProcResult;

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
    pub inode: u32,
}

/// Parses an address in the form 00010203:1234
///
/// Also supports IPv6
///
/// Panics if unparsable
fn parse_addressport_str(s: &str) -> SocketAddr {
    let mut las = s.split(":");
    let ip_part = las.next().expect("ip_part");
    let port = las.next().expect("port");
    let port = u16::from_str_radix(port, 16).unwrap();

    if ip_part.len() == 8 {
        let bytes = hex::decode(&ip_part).unwrap();
        let ip_u32 = NetworkEndian::read_u32(&bytes);

        let ip = Ipv4Addr::new(
            (ip_u32 & 0xff) as u8,
            ((ip_u32 & 0xff << 8) >> 8) as u8,
            ((ip_u32 & 0xff << 16) >> 16) as u8,
            ((ip_u32 & 0xff << 24) >> 24) as u8,
        );

        SocketAddr::V4(SocketAddrV4::new(ip, port))
    } else if ip_part.len() == 32 {
        let bytes = hex::decode(&ip_part).unwrap();
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

        SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))
    } else {
        panic!("Unable to parse {:?} as an address:port", s)
    }
}

fn read_tcp_table<R: Read>(reader: BufReader<R>) -> ProcResult<Vec<TcpNetEntry>> {
    let mut vec = Vec::new();

    // first line is a header we need to skip
    for line in reader.lines().skip(1) {
        let line = proctry!(line);
        let mut s = line.split_whitespace();
        s.next();
        let local_address = s.next().expect("tcp::local_address");
        let rem_address = s.next().expect("tcp::rem_address");
        let state = s.next().expect("tcp::st");
        s.next(); // skip tx_queue:rx_queue
        s.next(); // skip tr and tm->when
        s.next(); // skip retrnsmt
        s.next(); // skip uid
        s.next(); // skip timeout
        let inode = s.next().expect("tcp::inode");

        vec.push(TcpNetEntry {
            local_address: parse_addressport_str(local_address),
            remote_address: parse_addressport_str(rem_address),
            state: TcpState::from_u8(u8::from_str_radix(state, 16).unwrap()).unwrap(),
            inode: u32::from_str_radix(inode, 10).unwrap(),
        });
    }

    ProcResult::Ok(vec)
}

/// Reads the tcp socket table
pub fn tcp() -> ProcResult<Vec<TcpNetEntry>> {
    use std::fs::File;
    let file = proctry!(File::open("/proc/net/tcp"));

    read_tcp_table(BufReader::new(file))
}

/// Reads the tcp6 socket table
pub fn tcp6() -> ProcResult<Vec<TcpNetEntry>> {
    use std::fs::File;
    let file = proctry!(File::open("/proc/net/tcp6"));

    read_tcp_table(BufReader::new(file))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use super::*;

    #[test]
    fn test_parse_ipaddr() {
        use std::str::FromStr;

        let addr = parse_addressport_str("0100007F:1234");
        assert_eq!(addr.port(), 0x1234);
        match addr.ip() {
            IpAddr::V4(addr) => assert_eq!(addr, Ipv4Addr::new(127, 0, 0, 1)),
            _ => panic!("Not IPv4"),
        }

        let addr = parse_addressport_str("5014002A18080140000000000E200000:0050");
        assert_eq!(addr.port(), 80);
        match addr.ip() {
            IpAddr::V6(addr) => {
                assert_eq!(addr, Ipv6Addr::from_str("0:e20::140:1808:2a:5014").unwrap())
            }
            _ => panic!("Not IPv6"),
        }

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

}
