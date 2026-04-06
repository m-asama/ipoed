// SPDX-License-Identifier: MIT
// Copyright(c) 2026 Masakazu Asama

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::rtnl::packets;
use crate::rtnl::{Family, RtnlSocket, Scope};

#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum IfaFlag {
    Secondary = libc::IFA_F_SECONDARY,
    NoDad = libc::IFA_F_NODAD,
    Optimistic = libc::IFA_F_OPTIMISTIC,
    DadFailed = libc::IFA_F_DADFAILED,
    HomeAddress = libc::IFA_F_HOMEADDRESS,
    Deprecated = libc::IFA_F_DEPRECATED,
    Tentative = libc::IFA_F_TENTATIVE,
    Permanent = libc::IFA_F_PERMANENT,
    ManageTempAddr = libc::IFA_F_MANAGETEMPADDR,
    NoPrefixRoute = libc::IFA_F_NOPREFIXROUTE,
    McAutoJoin = libc::IFA_F_MCAUTOJOIN,
    StablePrivacy = libc::IFA_F_STABLE_PRIVACY,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IfaFlags(HashSet<IfaFlag>);

impl IfaFlags {
    // Secondary
    /*
    pub fn has_secondary(&self) -> bool {
        self.0.contains(&IfaFlag::Secondary)
    }
    pub fn set_secondary(&mut self) -> bool {
        self.0.insert(IfaFlag::Secondary)
    }
    pub fn unset_secondary(&mut self) -> bool {
        self.0.remove(&IfaFlag::Secondary)
    }
     */

    // NoDad
    /*
    pub fn has_no_dad(&self) -> bool {
        self.0.contains(&IfaFlag::NoDad)
    }
    pub fn set_no_dad(&mut self) -> bool {
        self.0.insert(IfaFlag::NoDad)
    }
    pub fn unset_no_dad(&mut self) -> bool {
        self.0.remove(&IfaFlag::NoDad)
    }
     */

    // Optimistic
    /*
    pub fn has_optimistic(&self) -> bool {
        self.0.contains(&IfaFlag::Optimistic)
    }
    pub fn set_optimistic(&mut self) -> bool {
        self.0.insert(IfaFlag::Optimistic)
    }
    pub fn unset_optimistic(&mut self) -> bool {
        self.0.remove(&IfaFlag::Optimistic)
    }
     */

    // DadFailed
    /*
    pub fn has_dad_failed(&self) -> bool {
        self.0.contains(&IfaFlag::DadFailed)
    }
    pub fn set_dad_failed(&mut self) -> bool {
        self.0.insert(IfaFlag::DadFailed)
    }
    pub fn unset_dad_failed(&mut self) -> bool {
        self.0.remove(&IfaFlag::DadFailed)
    }
     */

    // HomeAddress
    /*
    pub fn has_home_address(&self) -> bool {
        self.0.contains(&IfaFlag::HomeAddress)
    }
    pub fn set_home_address(&mut self) -> bool {
        self.0.insert(IfaFlag::HomeAddress)
    }
    pub fn unset_home_address(&mut self) -> bool {
        self.0.remove(&IfaFlag::HomeAddress)
    }
     */

    // Deprecated
    /*
    pub fn has_deprecated(&self) -> bool {
        self.0.contains(&IfaFlag::Deprecated)
    }
    pub fn set_deprecated(&mut self) -> bool {
        self.0.insert(IfaFlag::Deprecated)
    }
    pub fn unset_deprecated(&mut self) -> bool {
        self.0.remove(&IfaFlag::Deprecated)
    }
     */

    // Tentative
    /*
    pub fn has_tentative(&self) -> bool {
        self.0.contains(&IfaFlag::Tentative)
    }
    pub fn set_tentative(&mut self) -> bool {
        self.0.insert(IfaFlag::Tentative)
    }
    pub fn unset_tentative(&mut self) -> bool {
        self.0.remove(&IfaFlag::Tentative)
    }
     */

    // Permanent
    /*
    pub fn has_permanent(&self) -> bool {
        self.0.contains(&IfaFlag::Permanent)
    }
    pub fn set_permanent(&mut self) -> bool {
        self.0.insert(IfaFlag::Permanent)
    }
    pub fn unset_permanent(&mut self) -> bool {
        self.0.remove(&IfaFlag::Permanent)
    }
     */

    // ManageTempAddr
    /*
    pub fn has_manage_temp_addr(&self) -> bool {
        self.0.contains(&IfaFlag::ManageTempAddr)
    }
    pub fn set_manage_temp_addr(&mut self) -> bool {
        self.0.insert(IfaFlag::ManageTempAddr)
    }
    pub fn unset_manage_temp_addr(&mut self) -> bool {
        self.0.remove(&IfaFlag::ManageTempAddr)
    }
     */

    // NoPrefixRoute
    /*
    pub fn has_no_prefix_route(&self) -> bool {
        self.0.contains(&IfaFlag::NoPrefixRoute)
    }
    pub fn set_no_prefix_route(&mut self) -> bool {
        self.0.insert(IfaFlag::NoPrefixRoute)
    }
    pub fn unset_no_prefix_route(&mut self) -> bool {
        self.0.remove(&IfaFlag::NoPrefixRoute)
    }
     */

    // McAutoJoin
    /*
    pub fn has_mc_auto_join(&self) -> bool {
        self.0.contains(&IfaFlag::McAutoJoin)
    }
    pub fn set_mc_auto_join(&mut self) -> bool {
        self.0.insert(IfaFlag::McAutoJoin)
    }
    pub fn unset_mc_auto_join(&mut self) -> bool {
        self.0.remove(&IfaFlag::McAutoJoin)
    }
     */

    // StablePrivacy
    /*
    pub fn has_stable_privacy(&self) -> bool {
        self.0.contains(&IfaFlag::StablePrivacy)
    }
    pub fn set_stable_privacy(&mut self) -> bool {
        self.0.insert(IfaFlag::StablePrivacy)
    }
    pub fn unset_stable_privacy(&mut self) -> bool {
        self.0.remove(&IfaFlag::StablePrivacy)
    }
     */
}

impl From<u8> for IfaFlags {
    fn from(flags_u8: u8) -> Self {
        let mut flags_set = HashSet::<IfaFlag>::new();
        if flags_u8 & IfaFlag::Secondary as u8 != 0 {
            flags_set.insert(IfaFlag::Secondary);
        }
        if flags_u8 & IfaFlag::NoDad as u8 != 0 {
            flags_set.insert(IfaFlag::NoDad);
        }
        if flags_u8 & IfaFlag::Optimistic as u8 != 0 {
            flags_set.insert(IfaFlag::Optimistic);
        }
        if flags_u8 & IfaFlag::DadFailed as u8 != 0 {
            flags_set.insert(IfaFlag::DadFailed);
        }
        if flags_u8 & IfaFlag::HomeAddress as u8 != 0 {
            flags_set.insert(IfaFlag::HomeAddress);
        }
        if flags_u8 & IfaFlag::Deprecated as u8 != 0 {
            flags_set.insert(IfaFlag::Deprecated);
        }
        if flags_u8 & IfaFlag::Tentative as u8 != 0 {
            flags_set.insert(IfaFlag::Tentative);
        }
        if flags_u8 & IfaFlag::Permanent as u8 != 0 {
            flags_set.insert(IfaFlag::Permanent);
        }
        IfaFlags(flags_set)
    }
}

impl Into<u8> for IfaFlags {
    fn into(self) -> u8 {
        let mut flags_u8: u8 = 0;
        if self.0.contains(&IfaFlag::Secondary) {
            flags_u8 |= IfaFlag::Secondary as u8;
        }
        if self.0.contains(&IfaFlag::NoDad) {
            flags_u8 |= IfaFlag::NoDad as u8;
        }
        if self.0.contains(&IfaFlag::Optimistic) {
            flags_u8 |= IfaFlag::Optimistic as u8;
        }
        if self.0.contains(&IfaFlag::DadFailed) {
            flags_u8 |= IfaFlag::DadFailed as u8;
        }
        if self.0.contains(&IfaFlag::HomeAddress) {
            flags_u8 |= IfaFlag::HomeAddress as u8;
        }
        if self.0.contains(&IfaFlag::Deprecated) {
            flags_u8 |= IfaFlag::Deprecated as u8;
        }
        if self.0.contains(&IfaFlag::Tentative) {
            flags_u8 |= IfaFlag::Tentative as u8;
        }
        if self.0.contains(&IfaFlag::Permanent) {
            flags_u8 |= IfaFlag::Permanent as u8;
        }
        flags_u8
    }
}

impl From<u32> for IfaFlags {
    fn from(flags_u32: u32) -> Self {
        let mut flags_set = IfaFlags::from(flags_u32 as u8).0;
        if flags_u32 & IfaFlag::ManageTempAddr as u32 != 0 {
            flags_set.insert(IfaFlag::ManageTempAddr);
        }
        if flags_u32 & IfaFlag::NoPrefixRoute as u32 != 0 {
            flags_set.insert(IfaFlag::NoPrefixRoute);
        }
        if flags_u32 & IfaFlag::McAutoJoin as u32 != 0 {
            flags_set.insert(IfaFlag::McAutoJoin);
        }
        if flags_u32 & IfaFlag::StablePrivacy as u32 != 0 {
            flags_set.insert(IfaFlag::StablePrivacy);
        }
        IfaFlags(flags_set)
    }
}

impl Into<u32> for IfaFlags {
    fn into(self) -> u32 {
        let flags_u8: u8 = self.clone().into();
        let mut flags_u32: u32 = flags_u8 as u32;
        if self.0.contains(&IfaFlag::ManageTempAddr) {
            flags_u32 |= IfaFlag::ManageTempAddr as u32;
        }
        if self.0.contains(&IfaFlag::NoPrefixRoute) {
            flags_u32 |= IfaFlag::NoPrefixRoute as u32;
        }
        if self.0.contains(&IfaFlag::McAutoJoin) {
            flags_u32 |= IfaFlag::McAutoJoin as u32;
        }
        if self.0.contains(&IfaFlag::StablePrivacy) {
            flags_u32 |= IfaFlag::StablePrivacy as u32;
        }
        flags_u32
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Addr {
    pub family: Family,
    pub scope: Scope,
    pub flags: IfaFlags,
    pub index: i32,
    pub address4: Option<Ipv4Addr>,
    pub address6: Option<Ipv6Addr>,
    pub prefixlen: u8,
}

impl RtnlSocket {
    fn dump_addrs(&mut self, family: Family) -> Result<Vec<Addr>, String> {
        self.seq += 1;
        let rtnl_msg = packets::RtnlMsg::Addr(packets::AddrMsg {
            nlmsg_type: libc::RTM_GETADDR,
            nlmsg_flags: libc::NLM_F_REQUEST as u16 | libc::NLM_F_DUMP as u16,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
            ifa_family: family.into(),
            ifa_prefixlen: 0,
            ifa_flags: 0,
            ifa_scope: libc::RT_SCOPE_UNIVERSE,
            ifa_index: 0,
            address4: None,
            address6: None,
            flags32: None,
        });
        self.dump(rtnl_msg, |rtnl_msg, vec| {
            if let packets::RtnlMsg::Addr(addr_msg) = rtnl_msg {
                let flags = if let Some(flags32) = addr_msg.flags32 {
                    IfaFlags::from(flags32)
                } else {
                    IfaFlags::from(addr_msg.ifa_flags)
                };
                vec.push(Addr {
                    family: family,
                    scope: Scope::from(addr_msg.ifa_scope),
                    flags: flags,
                    index: addr_msg.ifa_index,
                    address4: addr_msg.address4,
                    address6: addr_msg.address6,
                    prefixlen: addr_msg.ifa_prefixlen,
                });
            }
        })
    }

    /*
    fn dump_ipv4_addrs(&mut self) -> Result<Vec<Addr>, String> {
        self.dump_addrs(Family::Inet4)
    }
     */

    /*
    fn dump_ipv6_addrs(&mut self) -> Result<Vec<Addr>, String> {
        self.dump_addrs(Family::Inet6)
    }
     */

    fn mod_addr(
        &mut self,
        family: Family,
        cmd: &str,
        addr: &IpAddr,
        addr_len: u8,
        oif: i32,
    ) -> Result<(), String> {
        let nlmsg_type;
        let nlmsg_flags;
        match cmd {
            "rep" => {
                nlmsg_type = libc::RTM_NEWADDR;
                nlmsg_flags = libc::NLM_F_REQUEST as u16
                    | libc::NLM_F_CREATE as u16
                    | libc::NLM_F_REPLACE as u16;
            }
            "del" => {
                nlmsg_type = libc::RTM_DELADDR;
                nlmsg_flags = libc::NLM_F_REQUEST as u16;
            }
            _ => {
                return Err(format!("Unknown command"));
            }
        }
        let (address4, address6) = match addr {
            IpAddr::V4(addr) => (Some(*addr), None),
            IpAddr::V6(addr) => (None, Some(*addr)),
        };
        self.seq += 1;
        let rtnl_msg = packets::RtnlMsg::Addr(packets::AddrMsg {
            nlmsg_type: nlmsg_type,
            nlmsg_flags: nlmsg_flags,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
            ifa_family: family.into(),
            ifa_prefixlen: addr_len,
            ifa_flags: 0,
            ifa_scope: 0,
            ifa_index: oif,
            address4: address4,
            address6: address6,
            flags32: None,
        });
        self.write(rtnl_msg)
    }

    fn rep_ipv4_addr(&mut self, addr: &Ipv4Addr, addr_len: u8, oif: i32) -> Result<(), String> {
        self.mod_addr(
            Family::Inet4,
            "rep",
            &IpAddr::V4(addr.clone()),
            addr_len,
            oif,
        )
    }

    /*
    fn del_ipv4_addr(&mut self, addr: &Ipv4Addr, addr_len: u8, oif: i32) -> Result<(), String> {
        self.mod_addr(
            Family::Inet4,
            "del",
            &IpAddr::V4(addr.clone()),
            addr_len,
            oif,
        )
    }
     */

    fn rep_ipv6_addr(&mut self, addr: &Ipv6Addr, addr_len: u8, oif: i32) -> Result<(), String> {
        self.mod_addr(
            Family::Inet6,
            "rep",
            &IpAddr::V6(addr.clone()),
            addr_len,
            oif,
        )
    }

    fn del_ipv6_addr(&mut self, addr: &Ipv6Addr, addr_len: u8, oif: i32) -> Result<(), String> {
        self.mod_addr(
            Family::Inet6,
            "del",
            &IpAddr::V6(addr.clone()),
            addr_len,
            oif,
        )
    }
}

pub fn dump_addrs(family: Family) -> Result<Vec<Addr>, String> {
    let mut sock = RtnlSocket::new()?;
    sock.dump_addrs(family)
}

/*
pub fn dump_ipv4_addrs() -> Result<Vec<Addr>, String> {
    dump_addrs(Family::Inet4)
}
 */

pub fn dump_ipv6_addrs() -> Result<Vec<Addr>, String> {
    dump_addrs(Family::Inet6)
}

pub fn rep_ipv4_addr(addr: &Ipv4Addr, addr_len: u8, oif: i32) -> Result<(), String> {
    let mut sock = RtnlSocket::new()?;
    sock.rep_ipv4_addr(addr, addr_len, oif)
}

/*
pub fn del_ipv4_addr(addr: &Ipv4Addr, addr_len: u8, oif: i32) -> Result<(), String> {
    let mut sock = RtnlSocket::new()?;
    sock.del_ipv4_addr(addr, addr_len, oif)
}
 */

pub fn rep_ipv6_addr(addr: &Ipv6Addr, addr_len: u8, oif: i32) -> Result<(), String> {
    let mut sock = RtnlSocket::new()?;
    sock.rep_ipv6_addr(addr, addr_len, oif)
}

pub fn del_ipv6_addr(addr: &Ipv6Addr, addr_len: u8, oif: i32) -> Result<(), String> {
    let mut sock = RtnlSocket::new()?;
    sock.del_ipv6_addr(addr, addr_len, oif)
}
