// SPDX-License-Identifier: MIT
// Copyright(c) 2026 Masakazu Asama

use std::collections::HashSet;

use crate::rtnl::packets;

pub fn align_len(pos: usize) -> usize {
    (pos + 3) & !0x3
}

// IfType
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IfType {
    Ether,
    Loopback,
    Unknown(u16),
}

impl From<u16> for IfType {
    fn from(if_type: u16) -> Self {
        match if_type {
            libc::ARPHRD_ETHER => IfType::Ether,
            libc::ARPHRD_LOOPBACK => IfType::Loopback,
            _ => IfType::Unknown(if_type),
        }
    }
}

impl Into<u16> for IfType {
    fn into(self) -> u16 {
        match self {
            IfType::Ether => libc::ARPHRD_ETHER,
            IfType::Loopback => libc::ARPHRD_LOOPBACK,
            IfType::Unknown(if_type) => if_type,
        }
    }
}

// Scope
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Scope {
    Universe,
    Site,
    Link,
    Host,
    NoWhere,
    UserDefined(u8),
}

impl From<u8> for Scope {
    fn from(scope: u8) -> Self {
        match scope {
            libc::RT_SCOPE_UNIVERSE => Scope::Universe,
            libc::RT_SCOPE_SITE => Scope::Site,
            libc::RT_SCOPE_LINK => Scope::Link,
            libc::RT_SCOPE_HOST => Scope::Host,
            libc::RT_SCOPE_NOWHERE => Scope::NoWhere,
            _ => Scope::UserDefined(scope),
        }
    }
}

impl Into<u8> for Scope {
    fn into(self) -> u8 {
        match self {
            Scope::Universe => libc::RT_SCOPE_UNIVERSE as u8,
            Scope::Site => libc::RT_SCOPE_SITE as u8,
            Scope::Link => libc::RT_SCOPE_LINK as u8,
            Scope::Host => libc::RT_SCOPE_HOST as u8,
            Scope::NoWhere => libc::RT_SCOPE_NOWHERE as u8,
            Scope::UserDefined(scope) => scope,
        }
    }
}

// Family
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Family {
    Inet4 = libc::AF_INET as u8,
    Inet6 = libc::AF_INET6 as u8,
    Packet = libc::AF_PACKET as u8,
}

impl TryFrom<u8> for Family {
    type Error = String;
    fn try_from(family: u8) -> Result<Self, Self::Error> {
        match family as i32 {
            libc::AF_INET => Ok(Family::Inet4),
            libc::AF_INET6 => Ok(Family::Inet6),
            libc::AF_PACKET => Ok(Family::Packet),
            _ => Err(format!("Invalid family")),
        }
    }
}

impl Into<u8> for Family {
    fn into(self) -> u8 {
        match self {
            Family::Inet4 => libc::AF_INET as u8,
            Family::Inet6 => libc::AF_INET6 as u8,
            Family::Packet => libc::AF_PACKET as u8,
        }
    }
}

// Table
/*
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Table {
    Unspec,
    Compat,
    Default,
    Main,
    Local,
    UserDefined(u8),
}
 */

/*
impl From<u8> for Table {
    fn from(table: u8) -> Self {
        match table {
            libc::RT_TABLE_UNSPEC => Table::Unspec,
            libc::RT_TABLE_COMPAT => Table::Compat,
            libc::RT_TABLE_DEFAULT => Table::Default,
            libc::RT_TABLE_MAIN => Table::Main,
            libc::RT_TABLE_LOCAL => Table::Local,
            _ => Table::UserDefined(table),
        }
    }
}
 */

/*
impl Into<u8> for Table {
    fn into(self) -> u8 {
        match self {
            Table::Unspec => libc::RT_TABLE_UNSPEC as u8,
            Table::Compat => libc::RT_TABLE_COMPAT as u8,
            Table::Default => libc::RT_TABLE_DEFAULT as u8,
            Table::Main => libc::RT_TABLE_MAIN as u8,
            Table::Local => libc::RT_TABLE_LOCAL as u8,
            Table::UserDefined(table) => table,
        }
    }
}
 */

// RtType
/*
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RtType {
    Unspec,
    Unicast,
    Local,
    Broadcast,
    Anycast,
    Multicast,
    Blackhole,
    Unreachable,
    Prohibit,
    Throw,
    Nat,
    Xresolve,
    Unknown(u8),
}
 */

/*
impl From<u8> for RtType {
    fn from(rt_type: u8) -> Self {
        match rt_type {
            libc::RTN_UNSPEC => RtType::Unspec,
            libc::RTN_UNICAST => RtType::Unicast,
            libc::RTN_LOCAL => RtType::Local,
            libc::RTN_BROADCAST => RtType::Broadcast,
            libc::RTN_ANYCAST => RtType::Anycast,
            libc::RTN_MULTICAST => RtType::Multicast,
            libc::RTN_BLACKHOLE => RtType::Blackhole,
            libc::RTN_UNREACHABLE => RtType::Unreachable,
            libc::RTN_PROHIBIT => RtType::Prohibit,
            libc::RTN_THROW => RtType::Throw,
            libc::RTN_NAT => RtType::Nat,
            libc::RTN_XRESOLVE => RtType::Xresolve,
            _ => RtType::Unknown(rt_type),
        }
    }
}
 */

/*
impl Into<u8> for RtType {
    fn into(self) -> u8 {
        match self {
            RtType::Unspec => libc::RTN_UNSPEC as u8,
            RtType::Unicast => libc::RTN_UNICAST as u8,
            RtType::Local => libc::RTN_LOCAL as u8,
            RtType::Broadcast => libc::RTN_BROADCAST as u8,
            RtType::Anycast => libc::RTN_ANYCAST as u8,
            RtType::Multicast => libc::RTN_MULTICAST as u8,
            RtType::Blackhole => libc::RTN_BLACKHOLE as u8,
            RtType::Unreachable => libc::RTN_UNREACHABLE as u8,
            RtType::Prohibit => libc::RTN_PROHIBIT as u8,
            RtType::Throw => libc::RTN_THROW as u8,
            RtType::Nat => libc::RTN_NAT as u8,
            RtType::Xresolve => libc::RTN_XRESOLVE as u8,
            RtType::Unknown(rt_type) => rt_type,
        }
    }
}
 */

// Group
#[derive(Eq, Hash, PartialEq)]
pub enum Group {
    //None,
    Link,
}

pub struct GroupSet {
    group_set: HashSet<Group>,
}

impl GroupSet {
    pub fn new() -> Self {
        Self {
            group_set: HashSet::<Group>::new(),
        }
    }

    pub fn insert(&mut self, value: Group) -> bool {
        self.group_set.insert(value)
    }

    /*
    pub fn remove(&mut self, value: &Group) -> bool {
        self.group_set.remove(value)
    }
     */

    /*
    pub fn contains(&self, value: &Group) -> bool {
        self.group_set.contains(value)
    }
     */

    /*
    pub fn clear(&mut self) {
        self.group_set.clear()
    }
     */
}

impl Into<u32> for GroupSet {
    fn into(self) -> u32 {
        let mut groups = 0;
        for group in self.group_set {
            match group {
                //Group::None => {}
                Group::Link => {
                    groups |= 1 << (libc::RTNLGRP_LINK - 1);
                }
            }
        }
        groups
    }
}

// RtnlSocket
pub struct RtnlSocket {
    pub sockfd: libc::c_int,
    pub seq: u32,
}

impl RtnlSocket {
    pub fn new() -> Result<Self, String> {
        let sockfd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if sockfd < 0 {
            return Err(format!("socket error"));
        }
        let seq: u32 = rand::random();
        Ok(Self {
            sockfd: sockfd,
            seq: seq,
        })
    }

    pub fn bind(&self, groups: GroupSet) -> Result<(), String> {
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_groups = groups.into();
        let ret = unsafe {
            libc::bind(
                self.sockfd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(format!("bind error"));
        }
        Ok(())
    }

    pub fn write(&self, rtnl_msg: packets::RtnlMsg) -> Result<(), String> {
        let mut buf = [0u8; 8192];
        let bufcp = buf.as_ptr() as *const libc::c_void;
        let n1 = match rtnl_msg.serialize(&mut buf) {
            Ok(n1) => n1,
            Err(e) => return Err(format!("rtnl msg serialize error: {e}")),
        };
        let n2 = unsafe { libc::write(self.sockfd, bufcp, n1) } as usize;
        if n2 != n1 {
            return Err(format!("write error"));
        }
        Ok(())
    }

    pub fn read<T>(
        &self,
        cb: impl Fn(packets::RtnlMsg, &mut Vec<T>),
        once: bool,
    ) -> Result<Vec<T>, String> {
        let mut vec = Vec::<T>::new();
        let mut buf = [0u8; 8192];
        let bufmp = buf.as_mut_ptr() as *mut libc::c_void;
        'outer: loop {
            let tail = unsafe { libc::read(self.sockfd, bufmp, buf.len()) };
            if tail <= 0 {
                return Err(format!("read error"));
            }
            let tail = tail as usize;
            let mut pos = 0;
            loop {
                if tail == pos {
                    break;
                }
                if tail < pos + 4 {
                    return Err(format!("short message"));
                }
                let nlmsg_len = u32::from_ne_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
                if nlmsg_len == 0 {
                    return Err(format!("invalid length"));
                }
                if tail < pos + nlmsg_len {
                    return Err(format!("short message"));
                }
                let rtnl_msg = match packets::RtnlMsg::parse(&buf[pos..pos + nlmsg_len]) {
                    Ok(rtnl_msg) => rtnl_msg,
                    Err(e) => return Err(format!("parse error: {e}")),
                };
                if let packets::RtnlMsg::Done(_) = &rtnl_msg {
                    break 'outer;
                }
                cb(rtnl_msg, &mut vec);
                pos += align_len(nlmsg_len);
            }
            if once {
                break;
            }
        }
        Ok(vec)
    }

    pub fn dump<T>(
        &mut self,
        rtnl_msg: packets::RtnlMsg,
        cb: impl Fn(packets::RtnlMsg, &mut Vec<T>),
    ) -> Result<Vec<T>, String> {
        self.write(rtnl_msg)?;
        self.read(cb, false)
    }
}
