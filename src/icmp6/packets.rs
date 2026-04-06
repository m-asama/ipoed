// SPDX-License-Identifier: MIT
// Copyright(c) 2026 Masakazu Asama

use std::collections::HashSet;
use std::net::Ipv6Addr;

// Source Link-layer Address Option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SrcLLAddrOpt {
    pub src_lladdr: [u8; 6],
}

impl SrcLLAddrOpt {
    const OPT_TYPE: u8 = 1;

    const FIXED_LEN: usize = 8;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0] = Self::OPT_TYPE; // Type
        buf[1] = 1; // Length
        buf[2..8].copy_from_slice(&self.src_lladdr);
        Ok(Self::FIXED_LEN)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_type = bytes[0];
        let opt_len = bytes[1];
        let opt_bytes_len = opt_len as usize * 8;
        if opt_type != Self::OPT_TYPE {
            return Err(format!("Invalid option type"));
        }
        if opt_bytes_len != Self::FIXED_LEN {
            return Err(format!("Invalid option length"));
        }
        let src_lladdr: [u8; 6] = bytes[2..8].try_into().unwrap();
        Ok(Self {
            src_lladdr: src_lladdr,
        })
    }
}

// Target Link-layer Address Option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TgtLLAddrOpt {
    pub tgt_lladdr: [u8; 6],
}

impl TgtLLAddrOpt {
    const OPT_TYPE: u8 = 2;

    const FIXED_LEN: usize = 8;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0] = Self::OPT_TYPE; // Type
        buf[1] = 1; // Length
        buf[2..8].copy_from_slice(&self.tgt_lladdr);
        Ok(Self::FIXED_LEN)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_type = bytes[0];
        let opt_len = bytes[1];
        let opt_bytes_len = opt_len as usize * 8;
        if opt_type != Self::OPT_TYPE {
            return Err(format!("Invalid option type"));
        }
        if opt_bytes_len != Self::FIXED_LEN {
            return Err(format!("Invalid option length"));
        }
        let tgt_lladdr: [u8; 6] = bytes[2..8].try_into().unwrap();
        Ok(Self {
            tgt_lladdr: tgt_lladdr,
        })
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum PrefixFlag {
    OnLink = 0x80,
    AutonomousAddrConf = 0x40,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrefixFlags(HashSet<PrefixFlag>);

impl PrefixFlags {
    #[allow(unused)]
    pub fn has_on_link(&self) -> bool {
        self.0.contains(&PrefixFlag::OnLink)
    }
    #[allow(unused)]
    pub fn set_on_link(&mut self) -> bool {
        self.0.insert(PrefixFlag::OnLink)
    }
    #[allow(unused)]
    pub fn unset_on_link(&mut self) -> bool {
        self.0.remove(&PrefixFlag::OnLink)
    }
    #[allow(unused)]
    pub fn has_autonomous_addr_conf(&self) -> bool {
        self.0.contains(&PrefixFlag::AutonomousAddrConf)
    }
    #[allow(unused)]
    pub fn set_autonomous_addr_conf(&mut self) -> bool {
        self.0.insert(PrefixFlag::AutonomousAddrConf)
    }
    #[allow(unused)]
    pub fn unset_autonomous_addr_conf(&mut self) -> bool {
        self.0.remove(&PrefixFlag::AutonomousAddrConf)
    }
}

impl From<u8> for PrefixFlags {
    fn from(flags_u8: u8) -> Self {
        let mut flags_set = HashSet::<PrefixFlag>::new();
        if flags_u8 & PrefixFlag::OnLink as u8 != 0 {
            flags_set.insert(PrefixFlag::OnLink);
        }
        if flags_u8 & PrefixFlag::AutonomousAddrConf as u8 != 0 {
            flags_set.insert(PrefixFlag::AutonomousAddrConf);
        }
        PrefixFlags(flags_set)
    }
}

impl Into<u8> for PrefixFlags {
    fn into(self) -> u8 {
        let mut flags_u8: u8 = 0;
        if self.0.contains(&PrefixFlag::OnLink) {
            flags_u8 |= PrefixFlag::OnLink as u8;
        }
        if self.0.contains(&PrefixFlag::AutonomousAddrConf) {
            flags_u8 |= PrefixFlag::AutonomousAddrConf as u8;
        }
        flags_u8
    }
}

// Prefix Information Option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrefixInfoOpt {
    pub prefix_len: u8,
    pub flags: PrefixFlags,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub prefix: Ipv6Addr,
}

impl PrefixInfoOpt {
    const OPT_TYPE: u8 = 3;

    const FIXED_LEN: usize = 32;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0] = Self::OPT_TYPE;
        buf[1] = 4;
        buf[2] = self.prefix_len;
        buf[3] = self.flags.clone().into();
        buf[4..8].copy_from_slice(&self.valid_lifetime.to_be_bytes());
        buf[8..12].copy_from_slice(&self.preferred_lifetime.to_be_bytes());
        buf[12..16].copy_from_slice(&[0u8; 4]);
        buf[16..32].copy_from_slice(&self.prefix.octets());
        Ok(Self::FIXED_LEN)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_type = bytes[0];
        let opt_len = bytes[1];
        let opt_bytes_len = opt_len as usize * 8;
        if opt_type != Self::OPT_TYPE {
            return Err(format!("Invalid option type"));
        }
        if opt_bytes_len != Self::FIXED_LEN {
            return Err(format!("Invalid option length"));
        }
        let prefix_len = bytes[2];
        let flags = PrefixFlags::from(bytes[3]);
        let valid_lifetime = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let preferred_lifetime = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        let prefix: [u8; 16] = bytes[16..32].try_into().unwrap();
        let prefix = Ipv6Addr::from_octets(prefix);
        Ok(Self {
            prefix_len: prefix_len,
            flags: flags,
            valid_lifetime: valid_lifetime,
            preferred_lifetime: preferred_lifetime,
            prefix: prefix,
        })
    }
}

// Redirected Header Option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedirectedHdrOpt {
    pub iphdr_data: Vec<u8>,
}

impl RedirectedHdrOpt {
    const OPT_TYPE: u8 = 4;

    const FIXED_LEN: usize = 8;

    #[allow(unused)]
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN + self.iphdr_data.len() {
            return Err(format!("Too short buffer"));
        }
        if self.iphdr_data.len() % 8 != 0 {
            return Err(format!("Invalid iphdr_data"));
        }
        let opt_len = 1 + self.iphdr_data.len() / 8;
        if opt_len > u8::MAX as usize {
            return Err(format!("Invalid iphdr_data"));
        }
        buf[0] = Self::OPT_TYPE; // Type
        buf[1] = opt_len as u8; // Length
        buf[2..8].copy_from_slice(&[0u8; 6]); // Reserved
        buf[8..(8 + self.iphdr_data.len())].copy_from_slice(&self.iphdr_data);
        Ok(Self::FIXED_LEN + self.iphdr_data.len())
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 2 {
            return Err(format!("Too short option"));
        }
        let opt_type = bytes[0];
        let opt_len = bytes[1];
        let opt_bytes_len = opt_len as usize * 8;
        if opt_type != Self::OPT_TYPE {
            return Err(format!("Invalid option type"));
        }
        if opt_bytes_len > bytes.len() {
            return Err(format!("Invalid option length"));
        }
        let iphdr_data: Vec<u8> = bytes[Self::FIXED_LEN..opt_bytes_len].to_vec();
        Ok(Self {
            iphdr_data: iphdr_data,
        })
    }
}

// MTU Option
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MtuOpt {
    pub mtu: u32,
}

impl MtuOpt {
    const OPT_TYPE: u8 = 5;

    const FIXED_LEN: usize = 8;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0] = Self::OPT_TYPE;
        buf[1] = 1;
        buf[2..4].copy_from_slice(&[0u8; 2]);
        buf[4..8].copy_from_slice(&self.mtu.to_be_bytes());
        Ok(Self::FIXED_LEN)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short option"));
        }
        let opt_type = bytes[0];
        let opt_len = bytes[1];
        let opt_bytes_len = opt_len as usize * 8;
        if opt_type != Self::OPT_TYPE {
            return Err(format!("Invalid option type"));
        }
        if opt_bytes_len != Self::FIXED_LEN {
            return Err(format!("Invalid option length"));
        }
        let mtu: [u8; 4] = bytes[4..8].try_into().unwrap();
        let mtu = u32::from_be_bytes(mtu);
        Ok(Self { mtu: mtu })
    }
}

// Router Solicitation Message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtSolicitMsg {
    pub src_lladdr: Option<SrcLLAddrOpt>,
}

impl RtSolicitMsg {
    const MSG_TYPE: u8 = 133;
    const MSG_CODE: u8 = 0;

    const FIXED_LEN: usize = 8;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0] = Self::MSG_TYPE; // Type
        buf[1] = Self::MSG_CODE; // Code
        buf[2..4].copy_from_slice(&[0u8; 2]); // Checksum
        buf[4..8].copy_from_slice(&[0u8; 4]); // Reserved
        let mut pos = Self::FIXED_LEN;
        if let Some(src_lladdr) = &self.src_lladdr {
            if pos > buf.len() {
                return Err(format!("Too short buffer"));
            }
            pos += src_lladdr.serialize(&mut buf[pos..])?;
        }
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let msg_type = bytes[0];
        let msg_code = bytes[1];
        if msg_type != Self::MSG_TYPE || msg_code != Self::MSG_CODE {
            return Err(format!("Invalid message type/code"));
        }
        let mut src_lladdr: Option<SrcLLAddrOpt> = None;
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() - pos < 2 {
                return Err(format!("Too short option"));
            }
            let opt_type = bytes[pos];
            let opt_len = bytes[pos + 1];
            let opt_bytes_len = opt_len as usize * 8;
            if opt_bytes_len == 0 {
                return Err(format!("Invalid option length"));
            }
            match opt_type {
                SrcLLAddrOpt::OPT_TYPE => {
                    src_lladdr = Some(SrcLLAddrOpt::parse(&bytes[pos..])?);
                }
                _ => {
                    println!("Unknown ICMPv6 RS option type {}", opt_type);
                }
            }
            pos += opt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            src_lladdr: src_lladdr,
        })
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum RaFlag {
    ManagedAddrConfig = 0x80,
    OtherConfig = 0x40,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RaFlags(HashSet<RaFlag>);

impl RaFlags {
    pub fn has_managed_addr_config(&self) -> bool {
        self.0.contains(&RaFlag::ManagedAddrConfig)
    }
    #[allow(unused)]
    pub fn set_managed_addr_config(&mut self) -> bool {
        self.0.insert(RaFlag::ManagedAddrConfig)
    }
    #[allow(unused)]
    pub fn unset_managed_addr_config(&mut self) -> bool {
        self.0.remove(&RaFlag::ManagedAddrConfig)
    }
    pub fn has_other_config(&self) -> bool {
        self.0.contains(&RaFlag::OtherConfig)
    }
    #[allow(unused)]
    pub fn set_other_config(&mut self) -> bool {
        self.0.insert(RaFlag::OtherConfig)
    }
    #[allow(unused)]
    pub fn unset_other_config(&mut self) -> bool {
        self.0.remove(&RaFlag::OtherConfig)
    }
}

impl From<u8> for RaFlags {
    fn from(flags_u8: u8) -> Self {
        let mut flags_set = HashSet::<RaFlag>::new();
        if flags_u8 & RaFlag::ManagedAddrConfig as u8 != 0 {
            flags_set.insert(RaFlag::ManagedAddrConfig);
        }
        if flags_u8 & RaFlag::OtherConfig as u8 != 0 {
            flags_set.insert(RaFlag::OtherConfig);
        }
        RaFlags(flags_set)
    }
}

impl Into<u8> for RaFlags {
    fn into(self) -> u8 {
        let mut flags_u8: u8 = 0;
        if self.0.contains(&RaFlag::ManagedAddrConfig) {
            flags_u8 |= RaFlag::ManagedAddrConfig as u8;
        }
        if self.0.contains(&RaFlag::OtherConfig) {
            flags_u8 |= RaFlag::OtherConfig as u8;
        }
        flags_u8
    }
}

// Router Advertisement Message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtAdvertMsg {
    pub cur_hop_limit: u8,
    pub flags: RaFlags,
    pub router_lifetime: u16,
    pub reachable_time: u32,
    pub retrans_timer: u32,
    pub src_lladdr: Option<SrcLLAddrOpt>,
    pub mtu: Option<MtuOpt>,
    pub prefix_infos: Vec<PrefixInfoOpt>,
}

impl RtAdvertMsg {
    const MSG_TYPE: u8 = 134;
    const MSG_CODE: u8 = 0;

    const FIXED_LEN: usize = 16;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0] = Self::MSG_TYPE; // Type
        buf[1] = Self::MSG_CODE; // Code
        buf[2..4].copy_from_slice(&[0u8; 2]); // Checksum
        buf[4] = self.cur_hop_limit;
        buf[5] = self.flags.clone().into();
        buf[6..8].copy_from_slice(&self.router_lifetime.to_be_bytes());
        buf[8..12].copy_from_slice(&self.reachable_time.to_be_bytes());
        buf[12..16].copy_from_slice(&self.retrans_timer.to_be_bytes());
        let mut pos = Self::FIXED_LEN;
        if let Some(src_lladdr) = &self.src_lladdr {
            if pos > buf.len() {
                return Err(format!("Too short buffer"));
            }
            pos += src_lladdr.serialize(&mut buf[pos..])?;
        }
        if let Some(mtu) = &self.mtu {
            if pos > buf.len() {
                return Err(format!("Too short buffer"));
            }
            pos += mtu.serialize(&mut buf[pos..])?;
        }
        for prefix_info in &self.prefix_infos {
            if pos > buf.len() {
                return Err(format!("Too short buffer"));
            }
            pos += prefix_info.serialize(&mut buf[pos..])?;
        }
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let msg_type = bytes[0];
        let msg_code = bytes[1];
        if msg_type != Self::MSG_TYPE || msg_code != Self::MSG_CODE {
            return Err(format!("Invalid message type/code"));
        }
        let cur_hop_limit = bytes[4];
        let flags = RaFlags::from(bytes[5]);
        let router_lifetime = u16::from_be_bytes(bytes[6..8].try_into().unwrap());
        let reachable_time = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        let retrans_timer = u32::from_be_bytes(bytes[12..16].try_into().unwrap());
        let mut src_lladdr: Option<SrcLLAddrOpt> = None;
        let mut mtu: Option<MtuOpt> = None;
        let mut prefix_infos = Vec::<PrefixInfoOpt>::new();
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() - pos < 2 {
                return Err(format!("Too short option"));
            }
            let opt_type = bytes[pos];
            let opt_len = bytes[pos + 1];
            let opt_bytes_len = opt_len as usize * 8;
            if opt_bytes_len == 0 {
                return Err(format!("Invalid option length"));
            }
            match opt_type {
                SrcLLAddrOpt::OPT_TYPE => {
                    src_lladdr = Some(SrcLLAddrOpt::parse(&bytes[pos..])?);
                }
                MtuOpt::OPT_TYPE => {
                    mtu = Some(MtuOpt::parse(&bytes[pos..])?);
                }
                PrefixInfoOpt::OPT_TYPE => {
                    prefix_infos.push(PrefixInfoOpt::parse(&bytes[pos..])?);
                }
                _ => {
                    println!("Unknown ICMPv6 RA option type {}", opt_type);
                }
            }
            pos += opt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            cur_hop_limit: cur_hop_limit,
            flags: flags,
            router_lifetime: router_lifetime,
            reachable_time: reachable_time,
            retrans_timer: retrans_timer,
            src_lladdr: src_lladdr,
            mtu: mtu,
            prefix_infos: prefix_infos,
        })
    }
}

// Neighbor Solicitation Message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeighSolicitMsg {
    pub tgt_addr: Ipv6Addr,
    pub src_lladdr: Option<SrcLLAddrOpt>,
}

impl NeighSolicitMsg {
    const MSG_TYPE: u8 = 135;
    const MSG_CODE: u8 = 0;

    const FIXED_LEN: usize = 24;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0] = Self::MSG_TYPE; // Type
        buf[1] = Self::MSG_CODE; // Code
        buf[2..4].copy_from_slice(&[0u8; 2]); // Checksum
        buf[4..8].copy_from_slice(&[0u8; 4]); // Reserved
        buf[8..24].copy_from_slice(&self.tgt_addr.octets());
        let mut pos = Self::FIXED_LEN;
        if let Some(src_lladdr) = &self.src_lladdr {
            if pos > buf.len() {
                return Err(format!("Too short buffer"));
            }
            pos += src_lladdr.serialize(&mut buf[pos..])?;
        }
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let msg_type = bytes[0];
        let msg_code = bytes[1];
        if msg_type != Self::MSG_TYPE || msg_code != Self::MSG_CODE {
            return Err(format!("Invalid message type/code"));
        }
        let tgt_addr: [u8; 16] = bytes[8..24].try_into().unwrap();
        let tgt_addr = Ipv6Addr::from_octets(tgt_addr);
        let mut src_lladdr: Option<SrcLLAddrOpt> = None;
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() - pos < 2 {
                return Err(format!("Too short option"));
            }
            let opt_type = bytes[pos];
            let opt_len = bytes[pos + 1];
            let opt_bytes_len = opt_len as usize * 8;
            if opt_bytes_len == 0 {
                return Err(format!("Invalid option length"));
            }
            match opt_type {
                SrcLLAddrOpt::OPT_TYPE => {
                    src_lladdr = Some(SrcLLAddrOpt::parse(&bytes[pos..])?);
                }
                _ => {
                    println!("Unknown ICMPv6 NS option type {}", opt_type);
                }
            }
            pos += opt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            tgt_addr: tgt_addr,
            src_lladdr: src_lladdr,
        })
    }
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum NaFlag {
    Router = 0x80000000,
    Solicited = 0x40000000,
    Override = 0x20000000,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NaFlags(HashSet<NaFlag>);

impl NaFlags {
    #[allow(unused)]
    pub fn has_router(&self) -> bool {
        self.0.contains(&NaFlag::Router)
    }
    #[allow(unused)]
    pub fn set_router(&mut self) -> bool {
        self.0.insert(NaFlag::Router)
    }
    #[allow(unused)]
    pub fn unset_router(&mut self) -> bool {
        self.0.remove(&NaFlag::Router)
    }
    #[allow(unused)]
    pub fn has_solicited(&self) -> bool {
        self.0.contains(&NaFlag::Solicited)
    }
    pub fn set_solicited(&mut self) -> bool {
        self.0.insert(NaFlag::Solicited)
    }
    #[allow(unused)]
    pub fn unset_solicited(&mut self) -> bool {
        self.0.remove(&NaFlag::Solicited)
    }
    #[allow(unused)]
    pub fn has_override(&self) -> bool {
        self.0.contains(&NaFlag::Override)
    }
    #[allow(unused)]
    pub fn set_override(&mut self) -> bool {
        self.0.insert(NaFlag::Override)
    }
    #[allow(unused)]
    pub fn unset_override(&mut self) -> bool {
        self.0.remove(&NaFlag::Override)
    }
}

impl From<[u8; 4]> for NaFlags {
    fn from(flags_array: [u8; 4]) -> Self {
        let flags_u32 = u32::from_be_bytes(flags_array);
        NaFlags::from(flags_u32)
    }
}

impl Into<[u8; 4]> for NaFlags {
    fn into(self) -> [u8; 4] {
        let flags_u32: u32 = self.into();
        flags_u32.to_be_bytes()
    }
}

impl From<u32> for NaFlags {
    fn from(flags_u32: u32) -> Self {
        let mut flags_set = HashSet::<NaFlag>::new();
        if flags_u32 & NaFlag::Router as u32 != 0 {
            flags_set.insert(NaFlag::Router);
        }
        if flags_u32 & NaFlag::Solicited as u32 != 0 {
            flags_set.insert(NaFlag::Solicited);
        }
        if flags_u32 & NaFlag::Override as u32 != 0 {
            flags_set.insert(NaFlag::Override);
        }
        NaFlags(flags_set)
    }
}

impl Into<u32> for NaFlags {
    fn into(self) -> u32 {
        let mut flags_32: u32 = 0;
        if self.0.contains(&NaFlag::Router) {
            flags_32 |= NaFlag::Router as u32;
        }
        if self.0.contains(&NaFlag::Solicited) {
            flags_32 |= NaFlag::Solicited as u32;
        }
        if self.0.contains(&NaFlag::Override) {
            flags_32 |= NaFlag::Override as u32;
        }
        flags_32
    }
}

// Neighbor Advertisement Message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeighAdvertMsg {
    pub flags: NaFlags,
    pub tgt_addr: Ipv6Addr,
    pub tgt_lladdr: Option<TgtLLAddrOpt>,
}

impl NeighAdvertMsg {
    const MSG_TYPE: u8 = 136;
    const MSG_CODE: u8 = 0;

    const FIXED_LEN: usize = 24;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0] = Self::MSG_TYPE; // Type
        buf[1] = Self::MSG_CODE; // Code
        buf[2..4].copy_from_slice(&[0u8; 2]); // Checksum
        buf[4..8].copy_from_slice(&Into::<[u8; 4]>::into(self.flags.clone()));
        buf[8..24].copy_from_slice(&self.tgt_addr.octets());
        let mut pos = Self::FIXED_LEN;
        if let Some(tgt_lladdr) = &self.tgt_lladdr {
            if pos > buf.len() {
                return Err(format!("Too short buffer"));
            }
            pos += tgt_lladdr.serialize(&mut buf[pos..])?;
        }
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let msg_type = bytes[0];
        let msg_code = bytes[1];
        if msg_type != Self::MSG_TYPE || msg_code != Self::MSG_CODE {
            return Err(format!("Invalid message type/code"));
        }
        let flags = NaFlags::from(TryInto::<[u8; 4]>::try_into(&bytes[4..8]).unwrap());
        let tgt_addr: [u8; 16] = bytes[8..24].try_into().unwrap();
        let tgt_addr = Ipv6Addr::from_octets(tgt_addr);
        let mut tgt_lladdr: Option<TgtLLAddrOpt> = None;
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() - pos < 2 {
                return Err(format!("Too short option"));
            }
            let opt_type = bytes[pos];
            let opt_len = bytes[pos + 1];
            let opt_bytes_len = opt_len as usize * 8;
            if opt_bytes_len == 0 {
                return Err(format!("Invalid option length"));
            }
            match opt_type {
                TgtLLAddrOpt::OPT_TYPE => {
                    tgt_lladdr = Some(TgtLLAddrOpt::parse(&bytes[pos..])?);
                }
                _ => {
                    println!("Unknown ICMPv6 NA option type {}", opt_type);
                }
            }
            pos += opt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            flags: flags,
            tgt_addr: tgt_addr,
            tgt_lladdr: tgt_lladdr,
        })
    }
}

// Redirect Message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedirectMsg {
    pub tgt_addr: Ipv6Addr,
    pub dst_addr: Ipv6Addr,
    pub tgt_lladdr: Option<TgtLLAddrOpt>,
    pub redirected_hdr: Option<RedirectedHdrOpt>,
}

impl RedirectMsg {
    const MSG_TYPE: u8 = 137;
    const MSG_CODE: u8 = 0;

    const FIXED_LEN: usize = 40;

    #[allow(unused)]
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        if buf.len() < Self::FIXED_LEN {
            return Err(format!("Too short buffer"));
        }
        buf[0] = Self::MSG_TYPE; // Type
        buf[1] = Self::MSG_CODE; // Code
        buf[2..4].copy_from_slice(&[0u8; 2]); // Checksum
        buf[4..8].copy_from_slice(&[0u8; 4]); // Reserved
        buf[8..24].copy_from_slice(&self.tgt_addr.octets()); // Target Address
        buf[24..40].copy_from_slice(&self.dst_addr.octets()); // Destination Address
        let mut pos = Self::FIXED_LEN;
        if let Some(tgt_lladdr) = &self.tgt_lladdr {
            if pos > buf.len() {
                return Err(format!("Too short buffer"));
            }
            pos += tgt_lladdr.serialize(&mut buf[pos..])?;
        }
        if let Some(redirected_hdr) = &self.redirected_hdr {
            if pos > buf.len() {
                return Err(format!("Too short buffer"));
            }
            pos += redirected_hdr.serialize(&mut buf[pos..])?;
        }
        Ok(pos)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(format!("Too short message"));
        }
        let msg_type = bytes[0];
        let msg_code = bytes[1];
        if msg_type != Self::MSG_TYPE || msg_code != Self::MSG_CODE {
            return Err(format!("Invalid message type/code"));
        }
        let tgt_addr: [u8; 16] = bytes[8..24].try_into().unwrap();
        let tgt_addr = Ipv6Addr::from_octets(tgt_addr);
        let dst_addr: [u8; 16] = bytes[24..40].try_into().unwrap();
        let dst_addr = Ipv6Addr::from_octets(dst_addr);
        let mut tgt_lladdr: Option<TgtLLAddrOpt> = None;
        let mut redirected_hdr: Option<RedirectedHdrOpt> = None;
        let mut pos = Self::FIXED_LEN;
        while pos < bytes.len() {
            if bytes.len() - pos < 2 {
                return Err(format!("Too short option"));
            }
            let opt_type = bytes[pos];
            let opt_len = bytes[pos + 1];
            let opt_bytes_len = opt_len as usize * 8;
            if opt_bytes_len == 0 {
                return Err(format!("Invalid option length"));
            }
            match opt_type {
                TgtLLAddrOpt::OPT_TYPE => {
                    tgt_lladdr = Some(TgtLLAddrOpt::parse(&bytes[pos..])?);
                }
                RedirectedHdrOpt::OPT_TYPE => {
                    redirected_hdr = Some(RedirectedHdrOpt::parse(&bytes[pos..])?);
                }
                _ => {
                    println!("Unknown ICMPv6 Redirect option type {}", opt_type);
                }
            }
            pos += opt_bytes_len;
        }
        if pos != bytes.len() {
            return Err(format!("Invalid option length"));
        }
        Ok(Self {
            tgt_addr: tgt_addr,
            dst_addr: dst_addr,
            tgt_lladdr: tgt_lladdr,
            redirected_hdr: redirected_hdr,
        })
    }
}

// ICMPv6 Packet
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Icmp6Msg {
    RtSolicit(RtSolicitMsg),
    RtAdvert(RtAdvertMsg),
    NeighSolicit(NeighSolicitMsg),
    NeighAdvert(NeighAdvertMsg),
    Redirect(RedirectMsg),
}

impl Icmp6Msg {
    #[allow(unused)]
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, String> {
        match self {
            Icmp6Msg::RtSolicit(msg) => msg.serialize(buf),
            Icmp6Msg::RtAdvert(msg) => msg.serialize(buf),
            Icmp6Msg::NeighSolicit(msg) => msg.serialize(buf),
            Icmp6Msg::NeighAdvert(msg) => msg.serialize(buf),
            Icmp6Msg::Redirect(msg) => msg.serialize(buf),
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 1 {
            return Err(format!("Too short message"));
        }
        let msg_type = bytes[0];
        match msg_type {
            RtSolicitMsg::MSG_TYPE => Ok(Icmp6Msg::RtSolicit(RtSolicitMsg::parse(bytes)?)),
            RtAdvertMsg::MSG_TYPE => Ok(Icmp6Msg::RtAdvert(RtAdvertMsg::parse(bytes)?)),
            NeighSolicitMsg::MSG_TYPE => Ok(Icmp6Msg::NeighSolicit(NeighSolicitMsg::parse(bytes)?)),
            NeighAdvertMsg::MSG_TYPE => Ok(Icmp6Msg::NeighAdvert(NeighAdvertMsg::parse(bytes)?)),
            RedirectMsg::MSG_TYPE => Ok(Icmp6Msg::Redirect(RedirectMsg::parse(bytes)?)),
            _ => Err(format!("Unknown message type")),
        }
    }
}
