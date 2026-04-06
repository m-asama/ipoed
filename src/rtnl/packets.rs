// SPDX-License-Identifier: MIT
// Copyright(c) 2026 Masakazu Asama

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

// NLMSG_DONE
#[derive(Debug, Eq, PartialEq)]
pub struct DoneMsg {
    // pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
    pub dump_done_errno: i32,
}

impl DoneMsg {
    const FIXED_LEN: usize = 20;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0..4].copy_from_slice(&Self::FIXED_LEN.to_ne_bytes());
        buf[4..6].copy_from_slice(&self.nlmsg_type.to_ne_bytes());
        buf[6..8].copy_from_slice(&self.nlmsg_flags.to_ne_bytes());
        buf[8..12].copy_from_slice(&self.nlmsg_seq.to_ne_bytes());
        buf[12..16].copy_from_slice(&self.nlmsg_pid.to_ne_bytes());
        buf[16..20].copy_from_slice(&self.dump_done_errno.to_ne_bytes());
        Ok(Self::FIXED_LEN)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let nlmsg_type = u16::from_ne_bytes(bytes[4..6].try_into().unwrap());
        let nlmsg_flags = u16::from_ne_bytes(bytes[6..8].try_into().unwrap());
        let nlmsg_seq = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        let nlmsg_pid = u32::from_ne_bytes(bytes[12..16].try_into().unwrap());
        let dump_done_errno = i32::from_ne_bytes(bytes[16..20].try_into().unwrap());
        Ok(Self {
            nlmsg_type: nlmsg_type,
            nlmsg_flags: nlmsg_flags,
            nlmsg_seq: nlmsg_seq,
            nlmsg_pid: nlmsg_pid,
            dump_done_errno: dump_done_errno,
        })
    }
}

//const IFLA_IPTUN_UNSPEC: u16 = 0;
const IFLA_IPTUN_LINK: u16 = 1;
const IFLA_IPTUN_LOCAL: u16 = 2;
const IFLA_IPTUN_REMOTE: u16 = 3;
const IFLA_IPTUN_TTL: u16 = 4;
//const IFLA_IPTUN_TOS: u16 = 5;
const IFLA_IPTUN_ENCAP_LIMIT: u16 = 6;
const IFLA_IPTUN_FLOWINFO: u16 = 7;
const IFLA_IPTUN_FLAGS: u16 = 8;
const IFLA_IPTUN_PROTO: u16 = 9;
//const IFLA_IPTUN_PMTUDISC: u16 = 10;
//const IFLA_IPTUN_6RD_PREFIX: u16 = 11;
//const IFLA_IPTUN_6RD_RELAY_PREFIX: u16 = 12;
//const IFLA_IPTUN_6RD_PREFIXLEN: u16 = 13;
//const IFLA_IPTUN_6RD_RELAY_PREFIXLEN: u16 = 14;
const IFLA_IPTUN_ENCAP_TYPE: u16 = 15;
const IFLA_IPTUN_ENCAP_FLAGS: u16 = 16;
const IFLA_IPTUN_ENCAP_SPORT: u16 = 17;
const IFLA_IPTUN_ENCAP_DPORT: u16 = 18;
//const IFLA_IPTUN_COLLECT_METADATA: u16 = 19;
const IFLA_IPTUN_FWMARK: u16 = 20;

// IFLA_INFO_KIND: "ip6tnl"
#[derive(Debug, Eq, PartialEq)]
pub struct Ip6tnlLinkinfo {
    pub link: Option<u32>,
    pub local: Option<Ipv6Addr>,
    pub remote: Option<Ipv6Addr>,
    pub ttl: Option<u8>,
    pub encap_limit: Option<u8>,
    pub flowinfo: Option<u32>,
    pub flags: Option<u32>,
    pub proto: Option<u8>,
    pub fwmark: Option<u32>,
    pub encap_type: Option<u16>,
    pub encap_sport: Option<u16>,
    pub encap_dport: Option<u16>,
    pub encap_flags: Option<u16>,
}

impl Ip6tnlLinkinfo {
    const FIXED_LEN: usize = 4;
    const KIND: &str = "ip6tnl";

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        let rta_type = libc::IFLA_LINKINFO as u16;
        buf[2..4].copy_from_slice(&rta_type.to_ne_bytes());
        let mut pos = Self::FIXED_LEN;
        {
            let pos_orig = pos;
            pos += 2;
            let rta_type = libc::IFLA_INFO_KIND as u16;
            buf[pos..pos + 2].copy_from_slice(&rta_type.to_ne_bytes());
            pos += 2;
            if buf.len() < pos + Ip6tnlLinkinfo::KIND.len() + 1 {
                return Err(format!("Too short buffer"));
            }
            buf[pos..pos + Ip6tnlLinkinfo::KIND.len()]
                .copy_from_slice(Ip6tnlLinkinfo::KIND.as_bytes());
            pos += super::align_len(Ip6tnlLinkinfo::KIND.len() + 1);
            let len = 4 + Ip6tnlLinkinfo::KIND.len() + 1;
            if len > u16::MAX as usize {
                return Err(format!("Too big data"));
            }
            let rta_len = len as u16;
            buf[pos_orig..pos_orig + 2].copy_from_slice(&rta_len.to_ne_bytes());
        }
        {
            let pos_orig = pos;
            pos += 2;
            let rta_type = libc::IFLA_INFO_DATA as u16;
            buf[pos..pos + 2].copy_from_slice(&rta_type.to_ne_bytes());
            pos += 2;
            if let Some(link) = &self.link {
                if buf.len() < pos + 4 + 4 {
                    return Err(format!("Too short buffer"));
                }
                let pos_orig = pos;
                pos += 2;
                let rta_type = IFLA_IPTUN_LINK;
                buf[pos..pos + 2].copy_from_slice(&rta_type.to_ne_bytes());
                pos += 2;
                buf[pos..pos + 4].copy_from_slice(&link.to_ne_bytes());
                pos += 4;
                let rta_len: u16 = 4 + 4;
                buf[pos_orig..pos_orig + 2].copy_from_slice(&rta_len.to_ne_bytes());
            }
            if let Some(local) = &self.local {
                if buf.len() < pos + 4 + 16 {
                    return Err(format!("Too short buffer"));
                }
                let pos_orig = pos;
                pos += 2;
                let rta_type = IFLA_IPTUN_LOCAL;
                buf[pos..pos + 2].copy_from_slice(&rta_type.to_ne_bytes());
                pos += 2;
                buf[pos..pos + 16].copy_from_slice(&local.octets());
                pos += 16;
                let rta_len: u16 = 4 + 16;
                buf[pos_orig..pos_orig + 2].copy_from_slice(&rta_len.to_ne_bytes());
            }
            if let Some(remote) = &self.remote {
                if buf.len() < pos + 4 + 16 {
                    return Err(format!("Too short buffer"));
                }
                let pos_orig = pos;
                pos += 2;
                let rta_type = IFLA_IPTUN_REMOTE;
                buf[pos..pos + 2].copy_from_slice(&rta_type.to_ne_bytes());
                pos += 2;
                buf[pos..pos + 16].copy_from_slice(&remote.octets());
                pos += 16;
                let rta_len: u16 = 4 + 16;
                buf[pos_orig..pos_orig + 2].copy_from_slice(&rta_len.to_ne_bytes());
            }
            if let Some(ttl) = &self.ttl {
                if buf.len() < pos + 4 + 1 {
                    return Err(format!("Too short buffer"));
                }
                let pos_orig = pos;
                pos += 2;
                let rta_type = IFLA_IPTUN_TTL;
                buf[pos..pos + 2].copy_from_slice(&rta_type.to_ne_bytes());
                pos += 2;
                buf[pos] = *ttl;
                pos += super::align_len(1);
                let rta_len: u16 = 4 + 1;
                buf[pos_orig..pos_orig + 2].copy_from_slice(&rta_len.to_ne_bytes());
            }
            if let Some(encap_limit) = &self.encap_limit {
                if buf.len() < pos + 4 + 1 {
                    return Err(format!("Too short buffer"));
                }
                let pos_orig = pos;
                pos += 2;
                let rta_type = IFLA_IPTUN_ENCAP_LIMIT;
                buf[pos..pos + 2].copy_from_slice(&rta_type.to_ne_bytes());
                pos += 2;
                buf[pos] = *encap_limit;
                pos += super::align_len(1);
                let rta_len: u16 = 4 + 1;
                buf[pos_orig..pos_orig + 2].copy_from_slice(&rta_len.to_ne_bytes());
            }
            if let Some(flowinfo) = &self.flowinfo {
                if buf.len() < pos + 4 + 4 {
                    return Err(format!("Too short buffer"));
                }
                let pos_orig = pos;
                pos += 2;
                let rta_type = IFLA_IPTUN_FLOWINFO;
                buf[pos..pos + 2].copy_from_slice(&rta_type.to_ne_bytes());
                pos += 2;
                buf[pos..pos + 4].copy_from_slice(&flowinfo.to_ne_bytes());
                pos += 4;
                let rta_len: u16 = 4 + 4;
                buf[pos_orig..pos_orig + 2].copy_from_slice(&rta_len.to_ne_bytes());
            }
            if let Some(flags) = &self.flags {
                if buf.len() < pos + 4 + 4 {
                    return Err(format!("Too short buffer"));
                }
                let pos_orig = pos;
                pos += 2;
                let rta_type = IFLA_IPTUN_FLAGS;
                buf[pos..pos + 2].copy_from_slice(&rta_type.to_ne_bytes());
                pos += 2;
                buf[pos..pos + 4].copy_from_slice(&flags.to_ne_bytes());
                pos += 4;
                let rta_len: u16 = 4 + 4;
                buf[pos_orig..pos_orig + 2].copy_from_slice(&rta_len.to_ne_bytes());
            }
            if let Some(proto) = &self.proto {
                if buf.len() < pos + 4 + 1 {
                    return Err(format!("Too short buffer"));
                }
                let pos_orig = pos;
                pos += 2;
                let rta_type = IFLA_IPTUN_PROTO;
                buf[pos..pos + 2].copy_from_slice(&rta_type.to_ne_bytes());
                pos += 2;
                buf[pos] = *proto;
                pos += super::align_len(1);
                let rta_len: u16 = 4 + 1;
                buf[pos_orig..pos_orig + 2].copy_from_slice(&rta_len.to_ne_bytes());
            }
            if let Some(fwmark) = &self.fwmark {
                if buf.len() < pos + 4 + 4 {
                    return Err(format!("Too short buffer"));
                }
                let pos_orig = pos;
                pos += 2;
                let rta_type = IFLA_IPTUN_FWMARK;
                buf[pos..pos + 2].copy_from_slice(&rta_type.to_ne_bytes());
                pos += 2;
                buf[pos..pos + 4].copy_from_slice(&fwmark.to_ne_bytes());
                pos += 4;
                let rta_len: u16 = 4 + 4;
                buf[pos_orig..pos_orig + 2].copy_from_slice(&rta_len.to_ne_bytes());
            }
            if let Some(encap_type) = &self.encap_type {
                if buf.len() < pos + 4 + 2 {
                    return Err(format!("Too short buffer"));
                }
                let pos_orig = pos;
                pos += 2;
                let rta_type = IFLA_IPTUN_ENCAP_TYPE;
                buf[pos..pos + 2].copy_from_slice(&rta_type.to_ne_bytes());
                pos += 2;
                buf[pos..pos + 2].copy_from_slice(&encap_type.to_ne_bytes());
                pos += super::align_len(2);
                let rta_len: u16 = 4 + 2;
                buf[pos_orig..pos_orig + 2].copy_from_slice(&rta_len.to_ne_bytes());
            }
            if let Some(encap_sport) = &self.encap_sport {
                if buf.len() < pos + 4 + 2 {
                    return Err(format!("Too short buffer"));
                }
                let pos_orig = pos;
                pos += 2;
                let rta_type = IFLA_IPTUN_ENCAP_SPORT;
                buf[pos..pos + 2].copy_from_slice(&rta_type.to_ne_bytes());
                pos += 2;
                buf[pos..pos + 2].copy_from_slice(&encap_sport.to_ne_bytes());
                pos += super::align_len(2);
                let rta_len: u16 = 4 + 2;
                buf[pos_orig..pos_orig + 2].copy_from_slice(&rta_len.to_ne_bytes());
            }
            if let Some(encap_dport) = &self.encap_dport {
                if buf.len() < pos + 4 + 2 {
                    return Err(format!("Too short buffer"));
                }
                let pos_orig = pos;
                pos += 2;
                let rta_type = IFLA_IPTUN_ENCAP_DPORT;
                buf[pos..pos + 2].copy_from_slice(&rta_type.to_ne_bytes());
                pos += 2;
                buf[pos..pos + 2].copy_from_slice(&encap_dport.to_ne_bytes());
                pos += super::align_len(2);
                let rta_len: u16 = 4 + 2;
                buf[pos_orig..pos_orig + 2].copy_from_slice(&rta_len.to_ne_bytes());
            }
            if let Some(encap_flags) = &self.encap_flags {
                if buf.len() < pos + 4 + 2 {
                    return Err(format!("Too short buffer"));
                }
                let pos_orig = pos;
                pos += 2;
                let rta_type = IFLA_IPTUN_ENCAP_FLAGS;
                buf[pos..pos + 2].copy_from_slice(&rta_type.to_ne_bytes());
                pos += 2;
                buf[pos..pos + 2].copy_from_slice(&encap_flags.to_ne_bytes());
                pos += super::align_len(2);
                let rta_len: u16 = 4 + 2;
                buf[pos_orig..pos_orig + 2].copy_from_slice(&rta_len.to_ne_bytes());
            }
            let len = pos - pos_orig;
            if len > u16::MAX as usize {
                return Err(format!("Too big data"));
            }
            let rta_len = len as u16;
            buf[pos_orig..pos_orig + 2].copy_from_slice(&rta_len.to_ne_bytes());
        }
        if pos > u16::MAX as usize {
            return Err(format!("Too big data"));
        }
        let rta_len = pos as u16;
        buf[0..2].copy_from_slice(&rta_len.to_ne_bytes());
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let mut data: Option<(usize, usize)> = None;
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + 4 {
                return Err(format!(
                    "Too short attribute: bytes.len() = {} pos = {}",
                    bytes.len(),
                    pos
                ));
            }
            let rta_len = u16::from_ne_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
            let rta_type = u16::from_ne_bytes(bytes[pos + 2..pos + 4].try_into().unwrap());
            if rta_len < 4 || bytes.len() < pos + rta_len {
                return Err(format!(
                    "Too short attribute: bytes.len() = {} rta_len = {} pos = {}",
                    bytes.len(),
                    rta_len,
                    pos
                ));
            }
            match rta_type {
                libc::IFLA_INFO_DATA => {
                    data = Some((pos, pos + rta_len));
                }
                _ => {}
            }
            pos += super::align_len(rta_len);
        }
        if pos != bytes.len() {
            return Err(format!("Invalid attribute length"));
        }
        let data = if let Some(data) = data {
            data
        } else {
            return Err(format!("IFLA_INFO_DATA not found"));
        };
        let bytes = &bytes[data.0..data.1];
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let mut link: Option<u32> = None;
        let mut local: Option<Ipv6Addr> = None;
        let mut remote: Option<Ipv6Addr> = None;
        let mut ttl: Option<u8> = None;
        let mut encap_limit: Option<u8> = None;
        let mut flowinfo: Option<u32> = None;
        let mut flags: Option<u32> = None;
        let mut proto: Option<u8> = None;
        let mut fwmark: Option<u32> = None;
        let mut encap_type: Option<u16> = None;
        let mut encap_sport: Option<u16> = None;
        let mut encap_dport: Option<u16> = None;
        let mut encap_flags: Option<u16> = None;
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + 4 {
                return Err(format!(
                    "Too short attribute: bytes.len() = {} pos = {}",
                    bytes.len(),
                    pos
                ));
            }
            let rta_len = u16::from_ne_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
            let rta_type = u16::from_ne_bytes(bytes[pos + 2..pos + 4].try_into().unwrap());
            if rta_len < 4 || bytes.len() < pos + rta_len {
                return Err(format!(
                    "Too short attribute: bytes.len() = {} rta_len = {} pos = {}",
                    bytes.len(),
                    rta_len,
                    pos
                ));
            }
            match rta_type {
                IFLA_IPTUN_LINK => {
                    if rta_len != 8 {
                        return Err(format!("Invalid link attribute"));
                    }
                    link = Some(u32::from_ne_bytes(
                        bytes[pos + 4..pos + 8].try_into().unwrap(),
                    ));
                }
                IFLA_IPTUN_LOCAL => {
                    if rta_len != 20 {
                        return Err(format!("Invalid local attribute"));
                    }
                    let tmp: [u8; 16] = bytes[pos + 4..pos + 20].try_into().unwrap();
                    local = Some(Ipv6Addr::from_octets(tmp));
                }
                IFLA_IPTUN_REMOTE => {
                    if rta_len != 20 {
                        return Err(format!("Invalid remote attribute"));
                    }
                    let tmp: [u8; 16] = bytes[pos + 4..pos + 20].try_into().unwrap();
                    remote = Some(Ipv6Addr::from_octets(tmp));
                }
                IFLA_IPTUN_TTL => {
                    if rta_len != 5 {
                        return Err(format!("Invalid ttl attribute"));
                    }
                    ttl = Some(bytes[pos + 4]);
                }
                IFLA_IPTUN_ENCAP_LIMIT => {
                    if rta_len != 5 {
                        return Err(format!("Invalid encap_limit attribute"));
                    }
                    encap_limit = Some(bytes[pos + 4]);
                }
                IFLA_IPTUN_FLOWINFO => {
                    if rta_len != 8 {
                        return Err(format!("Invalid flowinfo attribute"));
                    }
                    flowinfo = Some(u32::from_ne_bytes(
                        bytes[pos + 4..pos + 8].try_into().unwrap(),
                    ));
                }
                IFLA_IPTUN_FLAGS => {
                    if rta_len != 8 {
                        return Err(format!("Invalid flags attribute"));
                    }
                    flags = Some(u32::from_ne_bytes(
                        bytes[pos + 4..pos + 8].try_into().unwrap(),
                    ));
                }
                IFLA_IPTUN_PROTO => {
                    if rta_len != 5 {
                        return Err(format!("Invalid proto attribute"));
                    }
                    proto = Some(bytes[pos + 4]);
                }
                IFLA_IPTUN_FWMARK => {
                    if rta_len != 8 {
                        return Err(format!("Invalid fwmark attribute"));
                    }
                    fwmark = Some(u32::from_ne_bytes(
                        bytes[pos + 4..pos + 8].try_into().unwrap(),
                    ));
                }
                IFLA_IPTUN_ENCAP_TYPE => {
                    if rta_len != 6 {
                        return Err(format!("Invalid encap type attribute"));
                    }
                    encap_type = Some(u16::from_ne_bytes(
                        bytes[pos + 4..pos + 6].try_into().unwrap(),
                    ));
                }
                IFLA_IPTUN_ENCAP_SPORT => {
                    if rta_len != 6 {
                        return Err(format!("Invalid encap sport attribute"));
                    }
                    encap_sport = Some(u16::from_ne_bytes(
                        bytes[pos + 4..pos + 6].try_into().unwrap(),
                    ));
                }
                IFLA_IPTUN_ENCAP_DPORT => {
                    if rta_len != 6 {
                        return Err(format!("Invalid encap dport attribute"));
                    }
                    encap_dport = Some(u16::from_ne_bytes(
                        bytes[pos + 4..pos + 6].try_into().unwrap(),
                    ));
                }
                IFLA_IPTUN_ENCAP_FLAGS => {
                    if rta_len != 6 {
                        return Err(format!("Invalid encap flags attribute"));
                    }
                    encap_flags = Some(u16::from_ne_bytes(
                        bytes[pos + 4..pos + 6].try_into().unwrap(),
                    ));
                }
                _ => {}
            }
            pos += super::align_len(rta_len);
        }
        if pos != bytes.len() {
            return Err(format!("Invalid attribute length"));
        }
        Ok(Self {
            link: link,
            local: local,
            remote: remote,
            ttl: ttl,
            encap_limit: encap_limit,
            flowinfo: flowinfo,
            flags: flags,
            proto: proto,
            fwmark: fwmark,
            encap_type: encap_type,
            encap_sport: encap_sport,
            encap_dport: encap_dport,
            encap_flags: encap_flags,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct UnknownLinkinfo {
    pub data: Vec<u8>,
}

impl UnknownLinkinfo {
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < self.data.len() {
            return Err(format!("Too short buffer"));
        }
        buf[0..self.data.len()].copy_from_slice(&self.data);
        Ok(self.data.len())
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        Ok(Self {
            data: Vec::<u8>::from(bytes),
        })
    }
}

// IFLA_LINKINFO
#[derive(Debug, Eq, PartialEq)]
pub enum LinkinfoAttr {
    Ip6tnl(Ip6tnlLinkinfo),
    Unknown(UnknownLinkinfo),
}

impl LinkinfoAttr {
    const FIXED_LEN: usize = 4;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        match self {
            LinkinfoAttr::Ip6tnl(li) => li.serialize(buf),
            LinkinfoAttr::Unknown(li) => li.serialize(buf),
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let mut kind: Option<String> = None;
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + 4 {
                return Err(format!(
                    "Too short attribute: bytes.len() = {} pos = {}",
                    bytes.len(),
                    pos
                ));
            }
            let rta_len = u16::from_ne_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
            let rta_type = u16::from_ne_bytes(bytes[pos + 2..pos + 4].try_into().unwrap());
            if rta_len < 4 || bytes.len() < pos + rta_len {
                return Err(format!(
                    "Too short attribute: bytes.len() = {} rta_len = {} pos = {}",
                    bytes.len(),
                    rta_len,
                    pos
                ));
            }
            match rta_type {
                libc::IFLA_INFO_KIND => {
                    kind = Some(
                        String::from_utf8_lossy(&bytes[pos + 4..pos + rta_len - 1]).to_string(),
                    );
                }
                _ => {}
            }
            pos += super::align_len(rta_len);
        }
        if pos != bytes.len() {
            return Err(format!("Invalid attribute length"));
        }
        let kind = if let Some(kind) = kind {
            kind
        } else {
            return Err(format!("IFLA_INFO_KIND not found"));
        };
        match kind.as_ref() {
            Ip6tnlLinkinfo::KIND => Ok(LinkinfoAttr::Ip6tnl(Ip6tnlLinkinfo::parse(bytes)?)),
            _ => Ok(LinkinfoAttr::Unknown(UnknownLinkinfo::parse(bytes)?)),
        }
    }
}

// RTM_(NEW|DEGET|SET)LINK
#[derive(Debug, Eq, PartialEq)]
pub struct LinkMsg {
    // pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
    pub ifi_family: u8,
    // pub __ifi_pad: u8,
    pub ifi_type: u16,
    pub ifi_index: i32,
    pub ifi_flags: u32,
    pub ifi_change: u32,
    pub ifname: Option<String>,
    pub address: Option<[u8; 6]>,
    pub linkinfo: Option<LinkinfoAttr>,
}

impl LinkMsg {
    const FIXED_LEN: usize = 32;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[4..6].copy_from_slice(&self.nlmsg_type.to_ne_bytes());
        buf[6..8].copy_from_slice(&self.nlmsg_flags.to_ne_bytes());
        buf[8..12].copy_from_slice(&self.nlmsg_seq.to_ne_bytes());
        buf[12..16].copy_from_slice(&self.nlmsg_pid.to_ne_bytes());
        buf[16] = self.ifi_family;
        buf[17] = 0;
        buf[18..20].copy_from_slice(&self.ifi_type.to_ne_bytes());
        buf[20..24].copy_from_slice(&self.ifi_index.to_ne_bytes());
        buf[24..28].copy_from_slice(&self.ifi_flags.to_ne_bytes());
        buf[28..32].copy_from_slice(&self.ifi_change.to_ne_bytes());
        let mut pos = Self::FIXED_LEN;
        if let Some(ifname) = &self.ifname {
            if buf.len() < pos + 4 + ifname.len() + 1 {
                return Err(format!("Too short buffer"));
            }
            let rta_len: u16 = 4 + ifname.len() as u16 + 1;
            let rta_type: u16 = libc::IFLA_IFNAME;
            buf[pos..pos + 2].copy_from_slice(&rta_len.to_ne_bytes());
            buf[pos + 2..pos + 4].copy_from_slice(&rta_type.to_ne_bytes());
            buf[pos + 4..pos + 4 + ifname.len()].copy_from_slice(ifname.as_bytes());
            pos += super::align_len(4 + ifname.len() + 1);
        }
        if let Some(linkinfo) = &self.linkinfo {
            pos += linkinfo.serialize(&mut buf[pos..])?;
        }
        if pos > u32::MAX.try_into().unwrap() {
            return Err(format!("message length overflow"));
        }
        let nlmsg_len = pos as u32;
        buf[0..4].copy_from_slice(&nlmsg_len.to_ne_bytes());
        Ok(pos)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        //let nlmsg_len = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
        let nlmsg_type = u16::from_ne_bytes(bytes[4..6].try_into().unwrap());
        let nlmsg_flags = u16::from_ne_bytes(bytes[6..8].try_into().unwrap());
        let nlmsg_seq = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        let nlmsg_pid = u32::from_ne_bytes(bytes[12..16].try_into().unwrap());
        let ifi_family = bytes[16];
        let ifi_type = u16::from_ne_bytes(bytes[18..20].try_into().unwrap());
        let ifi_index = i32::from_ne_bytes(bytes[20..24].try_into().unwrap());
        let ifi_flags = u32::from_ne_bytes(bytes[24..28].try_into().unwrap());
        let ifi_change = u32::from_ne_bytes(bytes[28..32].try_into().unwrap());
        let mut ifname: Option<String> = None;
        let mut address: Option<[u8; 6]> = None;
        let mut linkinfo: Option<LinkinfoAttr> = None;
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + 4 {
                return Err(format!(
                    "Too short attribute: bytes.len() = {} pos = {}",
                    bytes.len(),
                    pos
                ));
            }
            let rta_len = u16::from_ne_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
            let rta_type = u16::from_ne_bytes(bytes[pos + 2..pos + 4].try_into().unwrap());
            if rta_len < 4 || bytes.len() < pos + rta_len {
                return Err(format!(
                    "Too short attribute: bytes.len() = {} rta_len = {} pos = {}",
                    bytes.len(),
                    rta_len,
                    pos
                ));
            }
            match rta_type {
                libc::IFLA_IFNAME => {
                    ifname = Some(
                        String::from_utf8_lossy(&bytes[pos + 4..pos + rta_len - 1]).to_string(),
                    );
                }
                libc::IFLA_ADDRESS => {
                    if rta_len == 10 {
                        address = Some(bytes[pos + 4..pos + 10].try_into().unwrap());
                    }
                }
                libc::IFLA_LINKINFO => {
                    linkinfo = Some(LinkinfoAttr::parse(&bytes[pos..pos + rta_len])?);
                }
                _ => {}
            }
            pos += super::align_len(rta_len);
        }
        if pos != bytes.len() {
            return Err(format!("Invalid attribute length"));
        }
        Ok(Self {
            nlmsg_type: nlmsg_type,
            nlmsg_flags: nlmsg_flags,
            nlmsg_seq: nlmsg_seq,
            nlmsg_pid: nlmsg_pid,
            ifi_family: ifi_family,
            ifi_type: ifi_type,
            ifi_index: ifi_index,
            ifi_flags: ifi_flags,
            ifi_change: ifi_change,
            ifname: ifname,
            address: address,
            linkinfo: linkinfo,
        })
    }
}

// RTM_(NEW|DEL|GET)ADDR
#[derive(Debug, Eq, PartialEq)]
pub struct AddrMsg {
    // pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
    pub ifa_family: u8,
    pub ifa_prefixlen: u8,
    pub ifa_flags: u8,
    pub ifa_scope: u8,
    pub ifa_index: i32,
    pub address4: Option<Ipv4Addr>,
    pub address6: Option<Ipv6Addr>,
    pub flags32: Option<u32>,
}

impl AddrMsg {
    const FIXED_LEN: usize = 24;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[4..6].copy_from_slice(&self.nlmsg_type.to_ne_bytes());
        buf[6..8].copy_from_slice(&self.nlmsg_flags.to_ne_bytes());
        buf[8..12].copy_from_slice(&self.nlmsg_seq.to_ne_bytes());
        buf[12..16].copy_from_slice(&self.nlmsg_pid.to_ne_bytes());
        buf[16] = self.ifa_family;
        buf[17] = self.ifa_prefixlen;
        buf[18] = self.ifa_flags;
        buf[19] = self.ifa_scope;
        buf[20..24].copy_from_slice(&self.ifa_index.to_ne_bytes());
        let mut pos = Self::FIXED_LEN;
        if let Some(address4) = &self.address4 {
            if buf.len() < pos + 16 {
                return Err(format!("Too short buffer"));
            }
            let rta_len: u16 = 8;
            let rta_type: u16 = libc::IFA_ADDRESS;
            buf[pos..pos + 2].copy_from_slice(&rta_len.to_ne_bytes());
            buf[pos + 2..pos + 4].copy_from_slice(&rta_type.to_ne_bytes());
            buf[pos + 4..pos + 8].copy_from_slice(&address4.octets());
            pos += 8;
            let rta_len: u16 = 8;
            let rta_type: u16 = libc::IFA_LOCAL;
            buf[pos..pos + 2].copy_from_slice(&rta_len.to_ne_bytes());
            buf[pos + 2..pos + 4].copy_from_slice(&rta_type.to_ne_bytes());
            buf[pos + 4..pos + 8].copy_from_slice(&address4.octets());
            pos += 8;
        }
        if let Some(address6) = &self.address6 {
            if buf.len() < pos + 20 {
                return Err(format!("Too short buffer"));
            }
            let rta_len: u16 = 20;
            let rta_type: u16 = libc::IFA_ADDRESS;
            buf[pos..pos + 2].copy_from_slice(&rta_len.to_ne_bytes());
            buf[pos + 2..pos + 4].copy_from_slice(&rta_type.to_ne_bytes());
            buf[pos + 4..pos + 20].copy_from_slice(&address6.octets());
            pos += 20;
        }
        if let Some(flags32) = &self.flags32 {
            if buf.len() < pos + 8 {
                return Err(format!("Too short buffer"));
            }
            let rta_len: u16 = 8;
            let rta_type: u16 = libc::IFA_FLAGS;
            buf[pos..pos + 2].copy_from_slice(&rta_len.to_ne_bytes());
            buf[pos + 2..pos + 4].copy_from_slice(&rta_type.to_ne_bytes());
            buf[pos + 4..pos + 8].copy_from_slice(&flags32.to_ne_bytes());
            pos += 8;
        }
        if pos > u32::MAX.try_into().unwrap() {
            return Err(format!("message length overflow"));
        }
        let nlmsg_len = pos as u32;
        buf[0..4].copy_from_slice(&nlmsg_len.to_ne_bytes());
        Ok(pos)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        //let nlmsg_len = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
        let nlmsg_type = u16::from_ne_bytes(bytes[4..6].try_into().unwrap());
        let nlmsg_flags = u16::from_ne_bytes(bytes[6..8].try_into().unwrap());
        let nlmsg_seq = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        let nlmsg_pid = u32::from_ne_bytes(bytes[12..16].try_into().unwrap());
        let ifa_family = bytes[16];
        let ifa_prefixlen = bytes[17];
        let ifa_flags = bytes[18];
        let ifa_scope = bytes[19];
        let ifa_index = i32::from_ne_bytes(bytes[20..24].try_into().unwrap());
        let mut address4: Option<Ipv4Addr> = None;
        let mut address6: Option<Ipv6Addr> = None;
        let mut flags32: Option<u32> = None;
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + 4 {
                return Err(format!(
                    "Too short attribute: bytes.len() = {} pos = {}",
                    bytes.len(),
                    pos
                ));
            }
            let rta_len = u16::from_ne_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
            let rta_type = u16::from_ne_bytes(bytes[pos + 2..pos + 4].try_into().unwrap());
            if rta_len < 4 || bytes.len() < pos + rta_len {
                return Err(format!(
                    "Too short attribute: bytes.len() = {} rta_len = {} pos = {}",
                    bytes.len(),
                    rta_len,
                    pos
                ));
            }
            match rta_type {
                libc::IFA_ADDRESS => match (ifa_family as i32, rta_len) {
                    (libc::AF_INET, 8) => {
                        let address: [u8; 4] = bytes[pos + 4..pos + 8].try_into().unwrap();
                        address4 = Some(Ipv4Addr::from_octets(address));
                    }
                    (libc::AF_INET6, 20) => {
                        let address: [u8; 16] = bytes[pos + 4..pos + 20].try_into().unwrap();
                        address6 = Some(Ipv6Addr::from_octets(address));
                    }
                    _ => return Err(format!("Invalid address attribute")),
                },
                libc::IFA_FLAGS => {
                    if rta_len != 8 {
                        return Err(format!("Invalid flags attribute"));
                    }
                    flags32 = Some(u32::from_ne_bytes(
                        bytes[pos + 4..pos + 8].try_into().unwrap(),
                    ));
                }
                _ => {}
            }
            pos += super::align_len(rta_len);
        }
        if pos != bytes.len() {
            return Err(format!("Invalid attribute length"));
        }
        Ok(Self {
            nlmsg_type: nlmsg_type,
            nlmsg_flags: nlmsg_flags,
            nlmsg_seq: nlmsg_seq,
            nlmsg_pid: nlmsg_pid,
            ifa_family: ifa_family,
            ifa_prefixlen: ifa_prefixlen,
            ifa_flags: ifa_flags,
            ifa_scope: ifa_scope,
            ifa_index: ifa_index,
            address4: address4,
            address6: address6,
            flags32: flags32,
        })
    }
}

// RTM_(NEW|DEL|GET)ROUTE
#[derive(Debug, Eq, PartialEq)]
pub struct RouteMsg {
    // pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
    pub rtm_family: u8,
    pub rtm_dst_len: u8,
    pub rtm_src_len: u8,
    pub rtm_tos: u8,
    pub rtm_table: u8,
    pub rtm_protocol: u8,
    pub rtm_scope: u8,
    pub rtm_type: u8,
    pub rtm_flags: u32,
    pub dst4: Option<Ipv4Addr>,
    pub dst6: Option<Ipv6Addr>,
    pub gateway4: Option<Ipv4Addr>,
    pub gateway6: Option<Ipv6Addr>,
    pub oif: Option<i32>,
}

impl RouteMsg {
    const FIXED_LEN: usize = 28;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[4..6].copy_from_slice(&self.nlmsg_type.to_ne_bytes());
        buf[6..8].copy_from_slice(&self.nlmsg_flags.to_ne_bytes());
        buf[8..12].copy_from_slice(&self.nlmsg_seq.to_ne_bytes());
        buf[12..16].copy_from_slice(&self.nlmsg_pid.to_ne_bytes());
        buf[16] = self.rtm_family;
        buf[17] = self.rtm_dst_len;
        buf[18] = self.rtm_src_len;
        buf[19] = self.rtm_tos;
        buf[20] = self.rtm_table;
        buf[21] = self.rtm_protocol;
        buf[22] = self.rtm_scope;
        buf[23] = self.rtm_type;
        buf[24..28].copy_from_slice(&self.rtm_flags.to_ne_bytes());
        let mut pos = Self::FIXED_LEN;
        if let Some(dst4) = &self.dst4 {
            if buf.len() < pos + 8 {
                return Err(format!("Too short buffer"));
            }
            let rta_len: u16 = 8;
            let rta_type: u16 = libc::RTA_DST;
            buf[pos..pos + 2].copy_from_slice(&rta_len.to_ne_bytes());
            buf[pos + 2..pos + 4].copy_from_slice(&rta_type.to_ne_bytes());
            buf[pos + 4..pos + 8].copy_from_slice(&dst4.octets());
            pos += 8;
        }
        if let Some(dst6) = &self.dst6 {
            if buf.len() < pos + 20 {
                return Err(format!("Too short buffer"));
            }
            let rta_len: u16 = 20;
            let rta_type: u16 = libc::RTA_DST;
            buf[pos..pos + 2].copy_from_slice(&rta_len.to_ne_bytes());
            buf[pos + 2..pos + 4].copy_from_slice(&rta_type.to_ne_bytes());
            buf[pos + 4..pos + 20].copy_from_slice(&dst6.octets());
            pos += 20;
        }
        if let Some(gateway4) = &self.gateway4 {
            if buf.len() < pos + 8 {
                return Err(format!("Too short buffer"));
            }
            let rta_len: u16 = 8;
            let rta_type: u16 = libc::RTA_GATEWAY;
            buf[pos..pos + 2].copy_from_slice(&rta_len.to_ne_bytes());
            buf[pos + 2..pos + 4].copy_from_slice(&rta_type.to_ne_bytes());
            buf[pos + 4..pos + 8].copy_from_slice(&gateway4.octets());
            pos += 8;
        }
        if let Some(gateway6) = &self.gateway6 {
            if buf.len() < pos + 20 {
                return Err(format!("Too short buffer"));
            }
            let rta_len: u16 = 20;
            let rta_type: u16 = libc::RTA_GATEWAY;
            buf[pos..pos + 2].copy_from_slice(&rta_len.to_ne_bytes());
            buf[pos + 2..pos + 4].copy_from_slice(&rta_type.to_ne_bytes());
            buf[pos + 4..pos + 20].copy_from_slice(&gateway6.octets());
            pos += 20;
        }
        if let Some(oif) = &self.oif {
            if buf.len() < pos + 8 {
                return Err(format!("Too short buffer"));
            }
            let rta_len: u16 = 8;
            let rta_type: u16 = libc::RTA_OIF;
            buf[pos..pos + 2].copy_from_slice(&rta_len.to_ne_bytes());
            buf[pos + 2..pos + 4].copy_from_slice(&rta_type.to_ne_bytes());
            buf[pos + 4..pos + 8].copy_from_slice(&oif.to_ne_bytes());
            pos += 8;
        }
        if pos > u32::MAX.try_into().unwrap() {
            return Err(format!("message length overflow"));
        }
        let nlmsg_len = pos as u32;
        buf[0..4].copy_from_slice(&nlmsg_len.to_ne_bytes());
        Ok(pos)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        //let nlmsg_len = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
        let nlmsg_type = u16::from_ne_bytes(bytes[4..6].try_into().unwrap());
        let nlmsg_flags = u16::from_ne_bytes(bytes[6..8].try_into().unwrap());
        let nlmsg_seq = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        let nlmsg_pid = u32::from_ne_bytes(bytes[12..16].try_into().unwrap());
        let rtm_family = bytes[16];
        let rtm_dst_len = bytes[17];
        let rtm_src_len = bytes[18];
        let rtm_tos = bytes[19];
        let rtm_table = bytes[20];
        let rtm_protocol = bytes[21];
        let rtm_scope = bytes[22];
        let rtm_type = bytes[23];
        let rtm_flags = u32::from_ne_bytes(bytes[24..28].try_into().unwrap());
        let mut dst4: Option<Ipv4Addr> = None;
        let mut dst6: Option<Ipv6Addr> = None;
        let mut gateway4: Option<Ipv4Addr> = None;
        let mut gateway6: Option<Ipv6Addr> = None;
        let mut oif: Option<i32> = None;
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() < pos + 4 {
                return Err(format!(
                    "Too short attribute: bytes.len() = {} pos = {}",
                    bytes.len(),
                    pos
                ));
            }
            let rta_len = u16::from_ne_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
            let rta_type = u16::from_ne_bytes(bytes[pos + 2..pos + 4].try_into().unwrap());
            if rta_len < 4 || bytes.len() < pos + rta_len {
                return Err(format!(
                    "Too short attribute: bytes.len() = {} rta_len = {} pos = {}",
                    bytes.len(),
                    rta_len,
                    pos
                ));
            }
            match rta_type {
                libc::RTA_DST => match (rtm_family as i32, rta_len) {
                    (libc::AF_INET, 8) => {
                        let dst: [u8; 4] = bytes[pos + 4..pos + 8].try_into().unwrap();
                        dst4 = Some(Ipv4Addr::from_octets(dst));
                    }
                    (libc::AF_INET6, 20) => {
                        let dst: [u8; 16] = bytes[pos + 4..pos + 20].try_into().unwrap();
                        dst6 = Some(Ipv6Addr::from_octets(dst));
                    }
                    _ => return Err(format!("Invalid dst attribute")),
                },
                libc::RTA_GATEWAY => match (rtm_family as i32, rta_len) {
                    (libc::AF_INET, 8) => {
                        let gateway: [u8; 4] = bytes[pos + 4..pos + 8].try_into().unwrap();
                        gateway4 = Some(Ipv4Addr::from_octets(gateway));
                    }
                    (libc::AF_INET6, 20) => {
                        let gateway: [u8; 16] = bytes[pos + 4..pos + 20].try_into().unwrap();
                        gateway6 = Some(Ipv6Addr::from_octets(gateway));
                    }
                    _ => return Err(format!("Invalid gateway attribute")),
                },
                libc::RTA_OIF => {
                    if rta_len != 8 {
                        return Err(format!("Invalid oif attribute"));
                    }
                    oif = Some(i32::from_ne_bytes(
                        bytes[pos + 4..pos + 8].try_into().unwrap(),
                    ));
                }
                _ => {}
            }
            pos += super::align_len(rta_len);
        }
        if pos != bytes.len() {
            return Err(format!("Invalid attribute length"));
        }
        Ok(Self {
            nlmsg_type: nlmsg_type,
            nlmsg_flags: nlmsg_flags,
            nlmsg_seq: nlmsg_seq,
            nlmsg_pid: nlmsg_pid,
            rtm_family: rtm_family,
            rtm_dst_len: rtm_dst_len,
            rtm_src_len: rtm_src_len,
            rtm_tos: rtm_tos,
            rtm_table: rtm_table,
            rtm_protocol: rtm_protocol,
            rtm_scope: rtm_scope,
            rtm_type: rtm_type,
            rtm_flags: rtm_flags,
            dst4: dst4,
            dst6: dst6,
            gateway4: gateway4,
            gateway6: gateway6,
            oif: oif,
        })
    }
}

// Routing Netlink Message
#[derive(Debug, Eq, PartialEq)]
pub enum RtnlMsg {
    Done(DoneMsg),
    Link(LinkMsg),
    Addr(AddrMsg),
    Route(RouteMsg),
}

impl RtnlMsg {
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        match self {
            RtnlMsg::Done(msg) => msg.serialize(buf),
            RtnlMsg::Link(msg) => msg.serialize(buf),
            RtnlMsg::Addr(msg) => msg.serialize(buf),
            RtnlMsg::Route(msg) => msg.serialize(buf),
        }
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 6 {
            return Err(format!("Too short message"));
        }
        let nlmsg_type = u16::from_ne_bytes(bytes[4..6].try_into().unwrap());
        const NLMSG_DONE: u16 = libc::NLMSG_DONE as u16;
        match nlmsg_type {
            NLMSG_DONE => Ok(RtnlMsg::Done(DoneMsg::parse(bytes)?)),
            libc::RTM_NEWLINK => Ok(RtnlMsg::Link(LinkMsg::parse(bytes)?)),
            libc::RTM_DELLINK => Ok(RtnlMsg::Link(LinkMsg::parse(bytes)?)),
            libc::RTM_GETLINK => Ok(RtnlMsg::Link(LinkMsg::parse(bytes)?)),
            libc::RTM_SETLINK => Ok(RtnlMsg::Link(LinkMsg::parse(bytes)?)),
            libc::RTM_NEWADDR => Ok(RtnlMsg::Addr(AddrMsg::parse(bytes)?)),
            libc::RTM_DELADDR => Ok(RtnlMsg::Addr(AddrMsg::parse(bytes)?)),
            libc::RTM_GETADDR => Ok(RtnlMsg::Addr(AddrMsg::parse(bytes)?)),
            libc::RTM_NEWROUTE => Ok(RtnlMsg::Route(RouteMsg::parse(bytes)?)),
            libc::RTM_DELROUTE => Ok(RtnlMsg::Route(RouteMsg::parse(bytes)?)),
            libc::RTM_GETROUTE => Ok(RtnlMsg::Route(RouteMsg::parse(bytes)?)),
            _ => Err(format!("Unknown nlmsg_type")),
        }
    }
}
