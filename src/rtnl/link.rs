// SPDX-License-Identifier: MIT
// Copyright(c) 2026 Masakazu Asama

use std::collections::HashSet;
use std::net::Ipv6Addr;

use crate::rtnl::packets;
use crate::rtnl::{Family, IfType, RtnlSocket};

#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum IfiFlag {
    Up = libc::IFF_UP,
    Broadcast = libc::IFF_BROADCAST,
    Debug = libc::IFF_DEBUG,
    Loopback = libc::IFF_LOOPBACK,
    PointToPoint = libc::IFF_POINTOPOINT,
    NoTrailers = libc::IFF_NOTRAILERS,
    Running = libc::IFF_RUNNING,
    NoArp = libc::IFF_NOARP,
    Promisc = libc::IFF_PROMISC,
    AllMulti = libc::IFF_ALLMULTI,
    Master = libc::IFF_MASTER,
    Slave = libc::IFF_SLAVE,
    Multicast = libc::IFF_MULTICAST,
    PortSel = libc::IFF_PORTSEL,
    AutoMedia = libc::IFF_AUTOMEDIA,
    Dynamic = libc::IFF_DYNAMIC,
    LowerUp = libc::IFF_LOWER_UP,
    Dormant = libc::IFF_DORMANT,
    Echo = libc::IFF_ECHO,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IfiFlags(HashSet<IfiFlag>);

impl IfiFlags {
    // Up
    pub fn has_up(&self) -> bool {
        self.0.contains(&IfiFlag::Up)
    }
    /*
    pub fn set_up(&mut self) -> bool {
        self.0.insert(IfiFlag::Up)
    }
    pub fn unset_up(&mut self) -> bool {
        self.0.remove(&IfiFlag::Up)
    }
     */

    // Broadcast
    /*
    pub fn has_broadcast(&self) -> bool {
        self.0.contains(&IfiFlag::Broadcast)
    }
    pub fn set_broadcast(&mut self) -> bool {
        self.0.insert(IfiFlag::Broadcast)
    }
    pub fn unset_broadcast(&mut self) -> bool {
        self.0.remove(&IfiFlag::Broadcast)
    }
     */

    // Debug
    /*
    pub fn has_debug(&self) -> bool {
        self.0.contains(&IfiFlag::Debug)
    }
    pub fn set_debug(&mut self) -> bool {
        self.0.insert(IfiFlag::Debug)
    }
    pub fn unset_debug(&mut self) -> bool {
        self.0.remove(&IfiFlag::Debug)
    }
     */

    // Loopback
    /*
    pub fn has_loopback(&self) -> bool {
        self.0.contains(&IfiFlag::Loopback)
    }
    pub fn set_loopback(&mut self) -> bool {
        self.0.insert(IfiFlag::Loopback)
    }
    pub fn unset_loopback(&mut self) -> bool {
        self.0.remove(&IfiFlag::Loopback)
    }
     */

    // PointToPoint
    /*
    pub fn has_point_to_point(&self) -> bool {
        self.0.contains(&IfiFlag::PointToPoint)
    }
    pub fn set_point_to_point(&mut self) -> bool {
        self.0.insert(IfiFlag::PointToPoint)
    }
    pub fn unset_point_to_point(&mut self) -> bool {
        self.0.remove(&IfiFlag::PointToPoint)
    }
     */

    // NoTrailers
    /*
    pub fn has_no_trailers(&self) -> bool {
        self.0.contains(&IfiFlag::NoTrailers)
    }
    pub fn set_no_trailers(&mut self) -> bool {
        self.0.insert(IfiFlag::NoTrailers)
    }
    pub fn unset_no_trailers(&mut self) -> bool {
        self.0.remove(&IfiFlag::NoTrailers)
    }
     */

    // Running
    /*
    pub fn has_running(&self) -> bool {
        self.0.contains(&IfiFlag::Running)
    }
    pub fn set_running(&mut self) -> bool {
        self.0.insert(IfiFlag::Running)
    }
    pub fn unset_running(&mut self) -> bool {
        self.0.remove(&IfiFlag::Running)
    }
     */

    // NoArp
    /*
    pub fn has_no_arp(&self) -> bool {
        self.0.contains(&IfiFlag::NoArp)
    }
    pub fn set_no_arp(&mut self) -> bool {
        self.0.insert(IfiFlag::NoArp)
    }
    pub fn unset_no_arp(&mut self) -> bool {
        self.0.remove(&IfiFlag::NoArp)
    }
     */

    // Promisc
    /*
    pub fn has_promisc(&self) -> bool {
        self.0.contains(&IfiFlag::Promisc)
    }
    pub fn set_promisc(&mut self) -> bool {
        self.0.insert(IfiFlag::Promisc)
    }
    pub fn unset_promisc(&mut self) -> bool {
        self.0.remove(&IfiFlag::Promisc)
    }
     */

    // AllMulti
    /*
    pub fn has_all_multi(&self) -> bool {
        self.0.contains(&IfiFlag::AllMulti)
    }
    pub fn set_all_multi(&mut self) -> bool {
        self.0.insert(IfiFlag::AllMulti)
    }
    pub fn unset_all_multi(&mut self) -> bool {
        self.0.remove(&IfiFlag::AllMulti)
    }
     */

    // Master
    /*
    pub fn has_master(&self) -> bool {
        self.0.contains(&IfiFlag::Master)
    }
    pub fn set_master(&mut self) -> bool {
        self.0.insert(IfiFlag::Master)
    }
    pub fn unset_master(&mut self) -> bool {
        self.0.remove(&IfiFlag::Master)
    }
     */

    // Slave
    /*
    pub fn has_slave(&self) -> bool {
        self.0.contains(&IfiFlag::Slave)
    }
    pub fn set_slave(&mut self) -> bool {
        self.0.insert(IfiFlag::Slave)
    }
    pub fn unset_slave(&mut self) -> bool {
        self.0.remove(&IfiFlag::Slave)
    }
     */

    // Multicast
    /*
    pub fn has_multicast(&self) -> bool {
        self.0.contains(&IfiFlag::Multicast)
    }
    pub fn set_multicast(&mut self) -> bool {
        self.0.insert(IfiFlag::Multicast)
    }
    pub fn unset_multicast(&mut self) -> bool {
        self.0.remove(&IfiFlag::Multicast)
    }
     */

    // PortSel
    /*
    pub fn has_port_sel(&self) -> bool {
        self.0.contains(&IfiFlag::PortSel)
    }
    pub fn set_port_sel(&mut self) -> bool {
        self.0.insert(IfiFlag::PortSel)
    }
    pub fn unset_port_sel(&mut self) -> bool {
        self.0.remove(&IfiFlag::PortSel)
    }
     */

    // AutoMedia
    /*
    pub fn has_auto_media(&self) -> bool {
        self.0.contains(&IfiFlag::AutoMedia)
    }
    pub fn set_auto_media(&mut self) -> bool {
        self.0.insert(IfiFlag::AutoMedia)
    }
    pub fn unset_auto_media(&mut self) -> bool {
        self.0.remove(&IfiFlag::AutoMedia)
    }
     */

    // Dynamic
    /*
    pub fn has_dynamic(&self) -> bool {
        self.0.contains(&IfiFlag::Dynamic)
    }
    pub fn set_dynamic(&mut self) -> bool {
        self.0.insert(IfiFlag::Dynamic)
    }
    pub fn unset_dynamic(&mut self) -> bool {
        self.0.remove(&IfiFlag::Dynamic)
    }
     */

    // LowerUp
    /*
    pub fn has_lower_up(&self) -> bool {
        self.0.contains(&IfiFlag::LowerUp)
    }
    pub fn set_lower_up(&mut self) -> bool {
        self.0.insert(IfiFlag::LowerUp)
    }
    pub fn unset_lower_up(&mut self) -> bool {
        self.0.remove(&IfiFlag::LowerUp)
    }
     */

    // Dormant
    /*
    pub fn has_dormant(&self) -> bool {
        self.0.contains(&IfiFlag::Dormant)
    }
    pub fn set_dormant(&mut self) -> bool {
        self.0.insert(IfiFlag::Dormant)
    }
    pub fn unset_dormant(&mut self) -> bool {
        self.0.remove(&IfiFlag::Dormant)
    }
     */

    // Echo
    /*
    pub fn has_echo(&self) -> bool {
        self.0.contains(&IfiFlag::Echo)
    }
    pub fn set_echo(&mut self) -> bool {
        self.0.insert(IfiFlag::Echo)
    }
    pub fn unset_echo(&mut self) -> bool {
        self.0.remove(&IfiFlag::Echo)
    }
     */
}

impl From<u32> for IfiFlags {
    fn from(flags_u32: u32) -> Self {
        let mut flags_set = HashSet::<IfiFlag>::new();
        if flags_u32 & IfiFlag::Up as u32 != 0 {
            flags_set.insert(IfiFlag::Up);
        }
        if flags_u32 & IfiFlag::Broadcast as u32 != 0 {
            flags_set.insert(IfiFlag::Broadcast);
        }
        if flags_u32 & IfiFlag::Debug as u32 != 0 {
            flags_set.insert(IfiFlag::Debug);
        }
        if flags_u32 & IfiFlag::Loopback as u32 != 0 {
            flags_set.insert(IfiFlag::Loopback);
        }
        if flags_u32 & IfiFlag::PointToPoint as u32 != 0 {
            flags_set.insert(IfiFlag::PointToPoint);
        }
        if flags_u32 & IfiFlag::NoTrailers as u32 != 0 {
            flags_set.insert(IfiFlag::NoTrailers);
        }
        if flags_u32 & IfiFlag::Running as u32 != 0 {
            flags_set.insert(IfiFlag::Running);
        }
        if flags_u32 & IfiFlag::NoArp as u32 != 0 {
            flags_set.insert(IfiFlag::NoArp);
        }
        if flags_u32 & IfiFlag::Promisc as u32 != 0 {
            flags_set.insert(IfiFlag::Promisc);
        }
        if flags_u32 & IfiFlag::AllMulti as u32 != 0 {
            flags_set.insert(IfiFlag::AllMulti);
        }
        if flags_u32 & IfiFlag::Master as u32 != 0 {
            flags_set.insert(IfiFlag::Master);
        }
        if flags_u32 & IfiFlag::Slave as u32 != 0 {
            flags_set.insert(IfiFlag::Slave);
        }
        if flags_u32 & IfiFlag::Multicast as u32 != 0 {
            flags_set.insert(IfiFlag::Multicast);
        }
        if flags_u32 & IfiFlag::PortSel as u32 != 0 {
            flags_set.insert(IfiFlag::PortSel);
        }
        if flags_u32 & IfiFlag::AutoMedia as u32 != 0 {
            flags_set.insert(IfiFlag::AutoMedia);
        }
        if flags_u32 & IfiFlag::Dynamic as u32 != 0 {
            flags_set.insert(IfiFlag::Dynamic);
        }
        if flags_u32 & IfiFlag::LowerUp as u32 != 0 {
            flags_set.insert(IfiFlag::LowerUp);
        }
        if flags_u32 & IfiFlag::Dormant as u32 != 0 {
            flags_set.insert(IfiFlag::Dormant);
        }
        if flags_u32 & IfiFlag::Echo as u32 != 0 {
            flags_set.insert(IfiFlag::Echo);
        }
        IfiFlags(flags_set)
    }
}

impl Into<u32> for IfiFlags {
    fn into(self) -> u32 {
        let mut flags_u32: u32 = 0;
        if self.0.contains(&IfiFlag::Up) {
            flags_u32 |= IfiFlag::Up as u32;
        }
        if self.0.contains(&IfiFlag::Broadcast) {
            flags_u32 |= IfiFlag::Broadcast as u32;
        }
        if self.0.contains(&IfiFlag::Debug) {
            flags_u32 |= IfiFlag::Debug as u32;
        }
        if self.0.contains(&IfiFlag::Loopback) {
            flags_u32 |= IfiFlag::Loopback as u32;
        }
        if self.0.contains(&IfiFlag::PointToPoint) {
            flags_u32 |= IfiFlag::PointToPoint as u32;
        }
        if self.0.contains(&IfiFlag::NoTrailers) {
            flags_u32 |= IfiFlag::NoTrailers as u32;
        }
        if self.0.contains(&IfiFlag::Running) {
            flags_u32 |= IfiFlag::Running as u32;
        }
        if self.0.contains(&IfiFlag::NoArp) {
            flags_u32 |= IfiFlag::NoArp as u32;
        }
        if self.0.contains(&IfiFlag::Promisc) {
            flags_u32 |= IfiFlag::Promisc as u32;
        }
        if self.0.contains(&IfiFlag::AllMulti) {
            flags_u32 |= IfiFlag::AllMulti as u32;
        }
        if self.0.contains(&IfiFlag::Master) {
            flags_u32 |= IfiFlag::Master as u32;
        }
        if self.0.contains(&IfiFlag::Slave) {
            flags_u32 |= IfiFlag::Slave as u32;
        }
        if self.0.contains(&IfiFlag::Multicast) {
            flags_u32 |= IfiFlag::Multicast as u32;
        }
        if self.0.contains(&IfiFlag::PortSel) {
            flags_u32 |= IfiFlag::PortSel as u32;
        }
        if self.0.contains(&IfiFlag::AutoMedia) {
            flags_u32 |= IfiFlag::AutoMedia as u32;
        }
        if self.0.contains(&IfiFlag::Dynamic) {
            flags_u32 |= IfiFlag::Dynamic as u32;
        }
        if self.0.contains(&IfiFlag::LowerUp) {
            flags_u32 |= IfiFlag::LowerUp as u32;
        }
        if self.0.contains(&IfiFlag::Dormant) {
            flags_u32 |= IfiFlag::Dormant as u32;
        }
        if self.0.contains(&IfiFlag::Echo) {
            flags_u32 |= IfiFlag::Echo as u32;
        }
        flags_u32
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Link {
    pub if_type: IfType,
    pub flags: IfiFlags,
    pub index: i32,
    pub ifname: Option<String>,
    pub address: Option<[u8; 6]>,
}

impl Link {
    pub fn ifname_s(&self) -> &str {
        if let Some(ifname) = &self.ifname {
            ifname
        } else {
            "(unknown)"
        }
    }
}

impl RtnlSocket {
    fn dump_links(&mut self) -> Result<Vec<Link>, String> {
        self.seq += 1;
        let rtnl_msg = packets::RtnlMsg::Link(packets::LinkMsg {
            nlmsg_type: libc::RTM_GETLINK,
            nlmsg_flags: libc::NLM_F_REQUEST as u16 | libc::NLM_F_DUMP as u16,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
            ifi_family: Family::Packet.into(),
            ifi_type: 0,
            ifi_index: 0,
            ifi_flags: 0,
            ifi_change: 0,
            ifname: None,
            address: None,
            linkinfo: None,
        });
        self.dump(rtnl_msg, |rtnl_msg, vec| {
            if let packets::RtnlMsg::Link(link_msg) = rtnl_msg {
                let if_type = IfType::from(link_msg.ifi_type);
                let flags = IfiFlags::from(link_msg.ifi_flags);
                vec.push(Link {
                    if_type: if_type,
                    flags: flags,
                    index: link_msg.ifi_index,
                    ifname: link_msg.ifname,
                    address: link_msg.address,
                });
            }
        })
    }

    fn get_link_by_name(&mut self, name: &str) -> Result<Link, String> {
        for link in self.dump_links()? {
            if let Some(ifname) = &link.ifname
                && ifname == name
            {
                return Ok(link);
            }
        }
        Err(format!("Not found"))
    }

    fn set_promisc(&mut self, if_index: i32, on: bool) -> Result<(), String> {
        let ifi_change = libc::IFF_PROMISC as u32;
        let ifi_flags = if on { libc::IFF_PROMISC as u32 } else { 0 };
        self.seq += 1;
        let rtnl_msg = packets::RtnlMsg::Link(packets::LinkMsg {
            nlmsg_type: libc::RTM_NEWLINK,
            nlmsg_flags: libc::NLM_F_REQUEST as u16,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
            ifi_family: 0,
            ifi_type: 0,
            ifi_index: if_index,
            ifi_flags: ifi_flags,
            ifi_change: ifi_change,
            ifname: None,
            address: None,
            linkinfo: None,
        });
        self.write(rtnl_msg)
    }

    fn mod_ip6tnl_link(
        &mut self,
        cmd: &str,
        if_index: i32,
        if_name: Option<&str>,
        up: Option<bool>,
        local: Option<&Ipv6Addr>,
        remote: Option<&Ipv6Addr>,
    ) -> Result<(), String> {
        let nlmsg_type;
        let nlmsg_flags;
        let ifi_change;
        let ifi_flags;
        let linkinfo;
        let ifname;
        match cmd {
            "new" | "set" => {
                let if_name = if let Some(if_name) = if_name {
                    if_name
                } else {
                    return Err(format!("name is required"));
                };
                let local = if let Some(local) = local {
                    local
                } else {
                    return Err(format!("local is required"));
                };
                let remote = if let Some(remote) = remote {
                    remote
                } else {
                    return Err(format!("remote is required"));
                };
                nlmsg_type = libc::RTM_NEWLINK;
                if cmd == "new" {
                    nlmsg_flags = libc::NLM_F_REQUEST as u16 | libc::NLM_F_CREATE as u16;
                } else {
                    nlmsg_flags = libc::NLM_F_REQUEST as u16;
                }
                if let Some(up) = up {
                    ifi_change = libc::IFF_UP as u32;
                    ifi_flags = if up { libc::IFF_UP as u32 } else { 0 };
                } else {
                    ifi_change = 0;
                    ifi_flags = 0;
                }
                ifname = Some(if_name.to_string());
                linkinfo = Some(packets::LinkinfoAttr::Ip6tnl(packets::Ip6tnlLinkinfo {
                    link: Some(0),
                    local: Some(local.clone()),
                    remote: Some(remote.clone()),
                    ttl: Some(64),
                    encap_limit: Some(4),
                    flowinfo: Some(0),
                    flags: Some(0x00030001),
                    proto: Some(4),
                    fwmark: Some(0),
                    encap_type: Some(0),
                    encap_sport: Some(0),
                    encap_dport: Some(0),
                    encap_flags: Some(0),
                }));
            }
            "del" => {
                nlmsg_type = libc::RTM_DELLINK;
                nlmsg_flags = libc::NLM_F_REQUEST as u16;
                ifi_change = 0;
                ifi_flags = 0;
                ifname = None;
                linkinfo = None;
            }
            _ => {
                return Err(format!("Unknown command"));
            }
        }
        self.seq += 1;
        let rtnl_msg = packets::RtnlMsg::Link(packets::LinkMsg {
            nlmsg_type: nlmsg_type,
            nlmsg_flags: nlmsg_flags,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
            ifi_family: 0,
            ifi_type: 0,
            ifi_index: if_index,
            ifi_flags: ifi_flags,
            ifi_change: ifi_change,
            ifname: ifname,
            address: None,
            linkinfo: linkinfo,
        });
        self.write(rtnl_msg)
    }

    fn new_ip6tnl_link(
        &mut self,
        if_name: &str,
        up: bool,
        local: &Ipv6Addr,
        remote: &Ipv6Addr,
    ) -> Result<(), String> {
        self.mod_ip6tnl_link("new", 0, Some(if_name), Some(up), Some(local), Some(remote))
    }

    fn del_ip6tnl_link(&mut self, if_index: i32) -> Result<(), String> {
        self.mod_ip6tnl_link("del", if_index, None, None, None, None)
    }

    fn set_ip6tnl_link(
        &mut self,
        if_index: i32,
        if_name: &str,
        up: Option<bool>,
        local: &Ipv6Addr,
        remote: &Ipv6Addr,
    ) -> Result<(), String> {
        self.mod_ip6tnl_link(
            "set",
            if_index,
            Some(if_name),
            up,
            Some(local),
            Some(remote),
        )
    }
}

pub fn dump_links() -> Result<Vec<Link>, String> {
    let mut sock = RtnlSocket::new()?;
    sock.dump_links()
}

pub fn get_link_by_name(name: &str) -> Result<Link, String> {
    let mut sock = RtnlSocket::new()?;
    sock.get_link_by_name(name)
}

pub fn set_promisc(if_index: i32, on: bool) -> Result<(), String> {
    let mut sock = RtnlSocket::new()?;
    sock.set_promisc(if_index, on)
}

pub fn new_ip6tnl_link(
    if_name: &str,
    up: bool,
    local: &Ipv6Addr,
    remote: &Ipv6Addr,
) -> Result<(), String> {
    let mut sock = RtnlSocket::new()?;
    sock.new_ip6tnl_link(if_name, up, local, remote)
}

pub fn del_ip6tnl_link(if_index: i32) -> Result<(), String> {
    let mut sock = RtnlSocket::new()?;
    sock.del_ip6tnl_link(if_index)
}

pub fn set_ip6tnl_link(
    if_index: i32,
    if_name: &str,
    up: Option<bool>,
    local: &Ipv6Addr,
    remote: &Ipv6Addr,
) -> Result<(), String> {
    let mut sock = RtnlSocket::new()?;
    sock.set_ip6tnl_link(if_index, if_name, up, local, remote)
}
