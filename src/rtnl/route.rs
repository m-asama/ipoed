// SPDX-License-Identifier: MIT
// Copyright(c) 2026 Masakazu Asama

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::rtnl::packets;
use crate::rtnl::{Family, RtnlSocket};

/*
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum RtmFlag {
    Notify = libc::RTM_F_NOTIFY,
    Cloned = libc::RTM_F_CLONED,
    Equalize = libc::RTM_F_EQUALIZE,
    Prefix = libc::RTM_F_PREFIX,
    LookupTble = libc::RTM_F_LOOKUP_TABLE,
    FibMatch = libc::RTM_F_FIB_MATCH,
}
 */

/*
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtmFlags(HashSet<RtmFlag>);
 */

/*
impl RtmFlags {
    // Notify
    pub fn has_notify(&self) -> bool {
        self.0.contains(&RtmFlag::Notify)
    }
    pub fn set_notify(&mut self) -> bool {
        self.0.insert(RtmFlag::Notify)
    }
    pub fn unset_notify(&mut self) -> bool {
        self.0.remove(&RtmFlag::Notify)
    }

    // Cloned
    pub fn has_cloned(&self) -> bool {
        self.0.contains(&RtmFlag::Cloned)
    }
    pub fn set_cloned(&mut self) -> bool {
        self.0.insert(RtmFlag::Cloned)
    }
    pub fn unset_cloned(&mut self) -> bool {
        self.0.remove(&RtmFlag::Cloned)
    }

    // Equalize
    pub fn has_equalize(&self) -> bool {
        self.0.contains(&RtmFlag::Equalize)
    }
    pub fn set_equalize(&mut self) -> bool {
        self.0.insert(RtmFlag::Equalize)
    }
    pub fn unset_equalize(&mut self) -> bool {
        self.0.remove(&RtmFlag::Equalize)
    }

    // Prefix
    pub fn has_prefix(&self) -> bool {
        self.0.contains(&RtmFlag::Prefix)
    }
    pub fn set_prefix(&mut self) -> bool {
        self.0.insert(RtmFlag::Prefix)
    }
    pub fn unset_prefix(&mut self) -> bool {
        self.0.remove(&RtmFlag::Prefix)
    }

    // LookupTble
    pub fn has_lookup_table(&self) -> bool {
        self.0.contains(&RtmFlag::LookupTble)
    }
    pub fn set_lookup_table(&mut self) -> bool {
        self.0.insert(RtmFlag::LookupTble)
    }
    pub fn unset_lookup_table(&mut self) -> bool {
        self.0.remove(&RtmFlag::LookupTble)
    }

    // FibMatch
    pub fn has_fib_match(&self) -> bool {
        self.0.contains(&RtmFlag::FibMatch)
    }
    pub fn set_fib_match(&mut self) -> bool {
        self.0.insert(RtmFlag::FibMatch)
    }
    pub fn unset_fib_match(&mut self) -> bool {
        self.0.remove(&RtmFlag::FibMatch)
    }
}
 */

/*
impl From<u32> for RtmFlags {
    fn from(flags_u32: u32) -> Self {
        let mut flags_set = HashSet::<RtmFlag>::new();
        if flags_u32 & RtmFlag::Notify as u32 != 0 {
            flags_set.insert(RtmFlag::Notify);
        }
        if flags_u32 & RtmFlag::Cloned as u32 != 0 {
            flags_set.insert(RtmFlag::Cloned);
        }
        if flags_u32 & RtmFlag::Equalize as u32 != 0 {
            flags_set.insert(RtmFlag::Equalize);
        }
        if flags_u32 & RtmFlag::Prefix as u32 != 0 {
            flags_set.insert(RtmFlag::Prefix);
        }
        if flags_u32 & RtmFlag::LookupTble as u32 != 0 {
            flags_set.insert(RtmFlag::LookupTble);
        }
        if flags_u32 & RtmFlag::FibMatch as u32 != 0 {
            flags_set.insert(RtmFlag::FibMatch);
        }
        RtmFlags(flags_set)
    }
}
 */

/*
impl Into<u32> for RtmFlags {
    fn into(self) -> u32 {
        let mut flags_u32: u32 = 0;
        if self.0.contains(&RtmFlag::Notify) {
            flags_u32 |= RtmFlag::Notify as u32;
        }
        if self.0.contains(&RtmFlag::Cloned) {
            flags_u32 |= RtmFlag::Cloned as u32;
        }
        if self.0.contains(&RtmFlag::Equalize) {
            flags_u32 |= RtmFlag::Equalize as u32;
        }
        if self.0.contains(&RtmFlag::Prefix) {
            flags_u32 |= RtmFlag::Prefix as u32;
        }
        if self.0.contains(&RtmFlag::LookupTble) {
            flags_u32 |= RtmFlag::LookupTble as u32;
        }
        if self.0.contains(&RtmFlag::FibMatch) {
            flags_u32 |= RtmFlag::FibMatch as u32;
        }
        flags_u32
    }
}
 */

/*
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Route {
    pub family: Family,
    pub table: Table,
    pub scope: Scope,
    pub rt_type: RtType,
    pub dst4: Option<Ipv4Addr>,
    pub dst6: Option<Ipv6Addr>,
    pub prefixlen: u8,
    pub gateway4: Option<Ipv4Addr>,
    pub gateway6: Option<Ipv6Addr>,
    pub oif: Option<i32>,
}
 */

impl RtnlSocket {
    /*
    fn dump_routes(&mut self, family: Family) -> Result<Vec<Route>, String> {
        self.seq += 1;
        let rtnl_msg = packets::RtnlMsg::Route(packets::RouteMsg {
            nlmsg_type: libc::RTM_GETROUTE,
            nlmsg_flags: libc::NLM_F_REQUEST as u16 | libc::NLM_F_DUMP as u16,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
            rtm_family: family.into(),
            rtm_dst_len: 0,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: libc::RT_TABLE_UNSPEC,
            rtm_protocol: libc::RTPROT_UNSPEC,
            rtm_scope: libc::RT_SCOPE_UNIVERSE,
            rtm_type: libc::RTN_UNSPEC,
            rtm_flags: 0,
            dst4: None,
            dst6: None,
            gateway4: None,
            gateway6: None,
            oif: None,
        });
        self.dump(rtnl_msg, |rtnl_msg, vec| {
            if let packets::RtnlMsg::Route(route_msg) = rtnl_msg {
                let dst4 = if family == Family::Inet4 && route_msg.dst4.is_none() {
                    Some(Ipv4Addr::from_octets([0; 4]))
                } else {
                    route_msg.dst4
                };
                let dst6 = if family == Family::Inet6 && route_msg.dst6.is_none() {
                    Some(Ipv6Addr::from_octets([0; 16]))
                } else {
                    route_msg.dst6
                };
                vec.push(Route {
                    family: family,
                    table: Table::from(route_msg.rtm_table),
                    scope: Scope::from(route_msg.rtm_scope),
                    rt_type: RtType::from(route_msg.rtm_type),
                    dst4: dst4,
                    dst6: dst6,
                    prefixlen: route_msg.rtm_dst_len,
                    gateway4: route_msg.gateway4,
                    gateway6: route_msg.gateway6,
                    oif: route_msg.oif,
                });
            }
        })
    }
     */

    /*
    fn dump_ipv4_routes(&mut self) -> Result<Vec<Route>, String> {
        self.dump_routes(Family::Inet4)
    }
     */

    /*
    fn dump_ipv6_routes(&mut self) -> Result<Vec<Route>, String> {
        self.dump_routes(Family::Inet6)
    }
     */

    fn mod_route(
        &mut self,
        family: Family,
        cmd: &str,
        dst: &IpAddr,
        dst_len: u8,
        gateway: Option<&IpAddr>,
        oif: i32,
    ) -> Result<(), String> {
        let nlmsg_type;
        let nlmsg_flags;
        let rtm_table;
        let rtm_scope;
        let rtm_type;
        match cmd {
            "rep" => {
                nlmsg_type = libc::RTM_NEWROUTE;
                nlmsg_flags = libc::NLM_F_REQUEST as u16
                    | libc::NLM_F_CREATE as u16
                    | libc::NLM_F_REPLACE as u16;
                rtm_table = libc::RT_TABLE_UNSPEC;
                rtm_scope = libc::RT_SCOPE_UNIVERSE;
                rtm_type = libc::RTN_UNICAST;
            }
            "del" => {
                nlmsg_type = libc::RTM_DELROUTE;
                nlmsg_flags = libc::NLM_F_REQUEST as u16;
                rtm_table = libc::RT_TABLE_MAIN;
                rtm_scope = libc::RT_SCOPE_NOWHERE;
                rtm_type = libc::RTN_UNSPEC;
            }
            _ => {
                return Err(format!("Unknown command"));
            }
        }
        let (dst4, dst6, gateway4, gateway6) = match (dst, gateway) {
            (IpAddr::V4(dst), Some(IpAddr::V4(gateway))) => {
                (Some(*dst), None, Some(*gateway), None)
            }
            (IpAddr::V6(dst), Some(IpAddr::V6(gateway))) => {
                (None, Some(*dst), None, Some(*gateway))
            }
            (IpAddr::V4(dst), None) => (Some(*dst), None, None, None),
            (IpAddr::V6(dst), None) => (None, Some(*dst), None, None),
            _ => {
                return Err(format!("Family mismatch"));
            }
        };
        self.seq += 1;
        let rtnl_msg = packets::RtnlMsg::Route(packets::RouteMsg {
            nlmsg_type: nlmsg_type,
            nlmsg_flags: nlmsg_flags,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
            rtm_family: family.into(),
            rtm_dst_len: dst_len,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: rtm_table,
            rtm_protocol: libc::RTPROT_UNSPEC,
            rtm_scope: rtm_scope,
            rtm_type: rtm_type,
            rtm_flags: 0,
            dst4: dst4,
            dst6: dst6,
            gateway4: gateway4,
            gateway6: gateway6,
            oif: Some(oif),
        });
        self.write(rtnl_msg)
    }

    fn rep_ipv4_route(
        &mut self,
        dst: &Ipv4Addr,
        dst_len: u8,
        gateway: Option<&Ipv4Addr>,
        oif: i32,
    ) -> Result<(), String> {
        let gateway4 = if let Some(gateway) = gateway {
            Some(&IpAddr::V4(gateway.clone()))
        } else {
            None
        };
        self.mod_route(
            Family::Inet4,
            "rep",
            &IpAddr::V4(dst.clone()),
            dst_len,
            gateway4,
            oif,
        )
    }

    /*
    fn del_ipv4_route(
        &mut self,
        dst: &Ipv4Addr,
        dst_len: u8,
        gateway: Option<&Ipv4Addr>,
        oif: i32,
    ) -> Result<(), String> {
        let gateway4 = if let Some(gateway) = gateway {
            Some(&IpAddr::V4(gateway.clone()))
        } else {
            None
        };
        self.mod_route(
            Family::Inet4,
            "del",
            &IpAddr::V4(dst.clone()),
            dst_len,
            gateway4,
            oif,
        )
    }
     */

    fn rep_ipv6_route(
        &mut self,
        dst: &Ipv6Addr,
        dst_len: u8,
        gateway: Option<&Ipv6Addr>,
        oif: i32,
    ) -> Result<(), String> {
        let gateway6 = if let Some(gateway) = gateway {
            Some(&IpAddr::V6(gateway.clone()))
        } else {
            None
        };
        self.mod_route(
            Family::Inet6,
            "rep",
            &IpAddr::V6(dst.clone()),
            dst_len,
            gateway6,
            oif,
        )
    }

    fn del_ipv6_route(
        &mut self,
        dst: &Ipv6Addr,
        dst_len: u8,
        gateway: Option<&Ipv6Addr>,
        oif: i32,
    ) -> Result<(), String> {
        let gateway6 = if let Some(gateway) = gateway {
            Some(&IpAddr::V6(gateway.clone()))
        } else {
            None
        };
        self.mod_route(
            Family::Inet6,
            "del",
            &IpAddr::V6(dst.clone()),
            dst_len,
            gateway6,
            oif,
        )
    }
}

/*
pub fn dump_routes(family: Family) -> Result<Vec<Route>, String> {
    let mut sock = RtnlSocket::new()?;
    sock.dump_routes(family)
}
 */

/*
pub fn dump_ipv4_routes() -> Result<Vec<Route>, String> {
    dump_routes(Family::Inet4)
}
 */

/*
pub fn dump_ipv6_routes() -> Result<Vec<Route>, String> {
    dump_routes(Family::Inet6)
}
 */

pub fn rep_ipv4_route(
    dst: &Ipv4Addr,
    dst_len: u8,
    gateway: Option<&Ipv4Addr>,
    oif: i32,
) -> Result<(), String> {
    let mut sock = RtnlSocket::new()?;
    sock.rep_ipv4_route(dst, dst_len, gateway, oif)
}

/*
pub fn del_ipv4_route(
    dst: &Ipv4Addr,
    dst_len: u8,
    gateway: Option<&Ipv4Addr>,
    oif: i32,
) -> Result<(), String> {
    let mut sock = RtnlSocket::new()?;
    sock.del_ipv4_route(dst, dst_len, gateway, oif)
}
 */

pub fn rep_ipv6_route(
    dst: &Ipv6Addr,
    dst_len: u8,
    gateway: Option<&Ipv6Addr>,
    oif: i32,
) -> Result<(), String> {
    let mut sock = RtnlSocket::new()?;
    sock.rep_ipv6_route(dst, dst_len, gateway, oif)
}

pub fn del_ipv6_route(
    dst: &Ipv6Addr,
    dst_len: u8,
    gateway: Option<&Ipv6Addr>,
    oif: i32,
) -> Result<(), String> {
    let mut sock = RtnlSocket::new()?;
    sock.del_ipv6_route(dst, dst_len, gateway, oif)
}
