// SPDX-License-Identifier: MIT
// Copyright(c) 2026 Masakazu Asama

use std::net::Ipv6Addr;

const CMSG_HDR_LEN: usize = 16;

// UnknownCmsg
#[derive(Debug, Eq, PartialEq)]
pub struct UnknownCmsg {
    pub cmsg_level: u32,
    pub cmsg_type: u32,
    pub cmsg_data: Vec<u8>,
}

impl UnknownCmsg {
    /*
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        let cmsg_buf_len = CMSG_HDR_LEN + self.cmsg_data.len();
        if buf.len() < cmsg_buf_len {
            return Err(format!("Too short buffer"));
        }
        let cmsg_len: u64 = cmsg_buf_len as u64;
        buf[0..8].copy_from_slice(&cmsg_len.to_ne_bytes());
        buf[8..12].copy_from_slice(&self.cmsg_level.to_ne_bytes());
        buf[12..16].copy_from_slice(&self.cmsg_type.to_ne_bytes());
        buf[16..cmsg_buf_len].copy_from_slice(&self.cmsg_data);
        Ok(cmsg_buf_len)
    }
     */

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < CMSG_HDR_LEN {
            return Err(format!("Too short message"));
        }
        let cmsg_len = u64::from_ne_bytes(bytes[0..8].try_into().unwrap()) as usize;
        let cmsg_level = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        let cmsg_type = u32::from_ne_bytes(bytes[12..16].try_into().unwrap());
        if bytes.len() != cmsg_len {
            return Err(format!("Too short message"));
        }
        let cmsg_data = Vec::<u8>::from(&bytes[16..cmsg_len]);
        Ok(Self {
            cmsg_level: cmsg_level,
            cmsg_type: cmsg_type,
            cmsg_data: cmsg_data,
        })
    }
}

// Ipv6PktinfoCmsg
#[derive(Debug, Eq, PartialEq)]
pub struct Ipv6PktinfoCmsg {
    pub ipi6_addr: Ipv6Addr,
    pub ipi6_ifindex: i32,
}

impl Ipv6PktinfoCmsg {
    const CMSG_LEVEL: u32 = 41;
    const CMSG_TYPE: u32 = 50;
    const FIXED_LEN: usize = 36;

    /*
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..8].copy_from_slice(&Self::FIXED_LEN.to_ne_bytes());
        buf[8..12].copy_from_slice(&Self::CMSG_LEVEL.to_ne_bytes());
        buf[12..16].copy_from_slice(&Self::CMSG_TYPE.to_ne_bytes());
        buf[16..32].copy_from_slice(&self.ipi6_addr.octets());
        buf[32..36].copy_from_slice(&self.ipi6_ifindex.to_ne_bytes());
        Ok(Self::FIXED_LEN)
    }
     */

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let cmsg_level = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        let cmsg_type = u32::from_ne_bytes(bytes[12..16].try_into().unwrap());
        if cmsg_level != Self::CMSG_LEVEL || cmsg_type != Self::CMSG_TYPE {
            return Err(format!("Invalid cmsg_level/cmsg_type"));
        }
        let cmsg_len = u64::from_ne_bytes(bytes[0..8].try_into().unwrap()) as usize;
        if bytes.len() != cmsg_len {
            return Err(format!("Invalid message length"));
        }
        let ipi6_addr: [u8; 16] = bytes[16..32].try_into().unwrap();
        let ipi6_addr = Ipv6Addr::from_octets(ipi6_addr);
        let ipi6_ifindex = i32::from_ne_bytes(bytes[32..36].try_into().unwrap());
        Ok(Self {
            ipi6_addr: ipi6_addr,
            ipi6_ifindex: ipi6_ifindex,
        })
    }
}

// Cmsg
#[derive(Debug, Eq, PartialEq)]
pub enum Cmsg {
    Ipv6Pktinfo(Ipv6PktinfoCmsg),
    Unknown(UnknownCmsg),
}

impl Cmsg {
    /*
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        match self {
            Cmsg::Ipv6Pktinfo(cmsg) => cmsg.serialize(buf),
            Cmsg::Unknown(cmsg) => cmsg.serialize(buf),
        }
    }
     */

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < CMSG_HDR_LEN {
            return Err(format!("Too short message"));
        }
        //let cmsg_len = u64::from_ne_bytes(bytes[0..8].try_into().unwrap()) as usize;
        let cmsg_level = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        let cmsg_type = u32::from_ne_bytes(bytes[12..16].try_into().unwrap());
        match (cmsg_level as i32, cmsg_type as i32) {
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                Ok(Cmsg::Ipv6Pktinfo(Ipv6PktinfoCmsg::parse(bytes)?))
            }
            _ => Ok(Cmsg::Unknown(UnknownCmsg::parse(bytes)?)),
        }
    }
}
