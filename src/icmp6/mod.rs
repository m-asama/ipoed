// SPDX-License-Identifier: MIT
// Copyright(c) 2026 Masakazu Asama

use std::net::Ipv6Addr;
use std::sync::mpsc;

mod packets;
pub use packets::*;

#[cfg(test)]
mod tests;

use crate::IpoedMsg;
use crate::utils;

const ALL_NODES_MCAST_ADDR: Ipv6Addr =
    Ipv6Addr::from_segments([0xff02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1]);
const ALL_ROUTERS_MCAST_ADDR: Ipv6Addr =
    Ipv6Addr::from_segments([0xff02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2]);

//pub const MAX_INITIAL_RTR_ADVERT_INTERVAL: u64 = 16000;
//pub const MAX_INITIAL_RTR_ADVERTISEMENTS: usize = 3;
//pub const MAX_FINAL_RTR_ADVERTISEMENTS: usize = 3;
//pub const MIN_DELAY_BETWEEN_RAS: u64 = 3000;
//pub const MAX_RA_DELAY_TIME: u64 = 500;

pub const MAX_RTR_SOLICITATION_DELAY: u64 = 1000;
pub const RTR_SOLICITATION_INTERVAL: u64 = 4000;
pub const MAX_RTR_SOLICITATIONS: usize = 3;

//pub const MAX_MULTICAST_SOLICIT: usize = 3;
//pub const MAX_UNICAST_SOLICIT: usize = 3;
//pub const MAX_ANYCAST_DELAY_TIME: u64 = 1000;
//pub const MAX_NEIGHBOR_ADVERTISEMENT: usize = 3;
//pub const REACHABLE_TIME: u64 = 30000;
//pub const RETRANS_TIMER: u64 = 1000;
//pub const DELAY_FIRST_PROBE_TIME: u64 = 5000;
//pub const MIN_RANDOM_FACTOR: f64 = 0.5;
//pub const MAX_RANDOM_FACTOR: f64 = 1.5;

pub const IPOED_MIN_RTR_ADV_INTERVAL: u64 = 100000;
pub const IPOED_MAX_RTR_ADV_INTERVAL: u64 = 300000;

#[derive(Debug, Eq, PartialEq)]
pub struct Icmp6Pkt {
    pub msg: packets::Icmp6Msg,
    pub iif: Option<i32>,
    pub src: Option<Ipv6Addr>,
    pub dst: Option<Ipv6Addr>,
}

pub fn send_rs(
    sk: libc::c_int,
    oif: i32,
    src_hwaddr: [u8; 6],
    src_lladdr: &Ipv6Addr,
) -> Result<(), String> {
    let src_hwaddr = Some(packets::SrcLLAddrOpt {
        src_lladdr: src_hwaddr,
    });
    let rs = packets::RtSolicitMsg {
        src_lladdr: src_hwaddr,
    };
    let mut buf = [0u8; 2048];
    let n = match rs.serialize(&mut buf) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    match utils::ipv6_sendmsg(
        sk,
        &mut buf[..n],
        Some(oif),
        Some(src_lladdr),
        &ALL_ROUTERS_MCAST_ADDR,
        0,
    ) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    Ok(())
}

pub fn send_ra(
    sk: libc::c_int,
    oif: i32,
    src_hwaddr: [u8; 6],
    src_lladdr: &Ipv6Addr,
    dst_addr: Option<&Ipv6Addr>,
    router_lifetime: u16,
    reachable_time: u32,
    retrans_timer: u32,
    prefix: &Ipv6Addr,
    prefix_len: u8,
    valid_lifetime: u32,
    preferred_lifetime: u32,
) -> Result<(), String> {
    let src_hwaddr = Some(packets::SrcLLAddrOpt {
        src_lladdr: src_hwaddr,
    });
    let prefix_infos = vec![packets::PrefixInfoOpt {
        prefix_len: prefix_len,
        flags: packets::PrefixFlags::from(
            packets::PrefixFlag::OnLink as u8 + packets::PrefixFlag::AutonomousAddrConf as u8,
        ),
        valid_lifetime: valid_lifetime,
        preferred_lifetime: preferred_lifetime,
        prefix: prefix.clone(),
    }];
    let ra = packets::RtAdvertMsg {
        cur_hop_limit: 64,
        flags: packets::RaFlags::from(packets::RaFlag::OtherConfig as u8),
        router_lifetime: router_lifetime,
        reachable_time: reachable_time,
        retrans_timer: retrans_timer,
        src_lladdr: src_hwaddr,
        mtu: None,
        prefix_infos: prefix_infos,
    };
    let mut buf = [0u8; 2048];
    let n = match ra.serialize(&mut buf) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    let daddr = if let Some(dst_addr) = dst_addr {
        dst_addr
    } else {
        &ALL_NODES_MCAST_ADDR
    };
    match utils::ipv6_sendmsg(sk, &mut buf[..n], Some(oif), Some(src_lladdr), daddr, 0) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    Ok(())
}

pub fn send_ns(
    sk: libc::c_int,
    oif: i32,
    src_hwaddr: [u8; 6],
    src_lladdr: &Ipv6Addr,
    tgt_addr: &Ipv6Addr,
) -> Result<(), String> {
    let src_hwaddr = Some(packets::SrcLLAddrOpt {
        src_lladdr: src_hwaddr,
    });
    let ns = packets::NeighSolicitMsg {
        tgt_addr: tgt_addr.clone(),
        src_lladdr: src_hwaddr,
    };
    let mut buf = [0u8; 2048];
    let n = match ns.serialize(&mut buf) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    match utils::ipv6_sendmsg(
        sk,
        &mut buf[..n],
        Some(oif),
        Some(src_lladdr),
        &ALL_NODES_MCAST_ADDR,
        0,
    ) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    Ok(())
}

pub fn send_na(
    sk: libc::c_int,
    oif: i32,
    src_lladdr: &Ipv6Addr,
    dst_addr: Option<&Ipv6Addr>,
    tgt_hwaddr: [u8; 6],
    tgt_addr: &Ipv6Addr,
) -> Result<(), String> {
    let tgt_hwaddr = Some(packets::TgtLLAddrOpt {
        tgt_lladdr: tgt_hwaddr,
    });
    let mut flags = packets::NaFlags::from(packets::NaFlag::Router as u32);
    let daddr = if let Some(dst_addr) = dst_addr {
        flags.set_solicited();
        dst_addr
    } else {
        &ALL_NODES_MCAST_ADDR
    };
    let na = packets::NeighAdvertMsg {
        flags: flags,
        tgt_addr: tgt_addr.clone(),
        tgt_lladdr: tgt_hwaddr,
    };
    let mut buf = [0u8; 2048];
    let n = match na.serialize(&mut buf) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    match utils::ipv6_sendmsg(sk, &mut buf[..n], Some(oif), Some(src_lladdr), daddr, 0) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    Ok(())
}

fn listener(sockfd: libc::c_int, if_index: i32, ch_tx: mpsc::Sender<IpoedMsg>) {
    loop {
        let mut buf = [0u8; 8192];
        let bufmp = buf.as_mut_ptr() as *mut libc::c_void;
        let n = unsafe { libc::read(sockfd, bufmp, buf.len()) };
        if n < 0 {
            println!("ICMPv6 socket read error: {n}");
            continue;
        }
        if n < 40 {
            println!("Too short message");
            continue;
        }
        let n = n as usize;
        let iif: Option<i32> = Some(if_index);
        let src: [u8; 16] = buf[8..24].try_into().unwrap();
        let src: Option<Ipv6Addr> = Some(Ipv6Addr::from_octets(src));
        let dst: [u8; 16] = buf[24..40].try_into().unwrap();
        let dst: Option<Ipv6Addr> = Some(Ipv6Addr::from_octets(dst));
        let msg = match packets::Icmp6Msg::parse(&buf[40..n]) {
            Ok(msg) => msg,
            Err(e) => {
                if e != "Unknown message type" {
                    println!("icmp6 parse error: {e}");
                }
                continue;
            }
        };
        if let Err(e) = ch_tx.send(IpoedMsg::Icmp6(Icmp6Pkt {
            msg: msg,
            iif: iif,
            src: src,
            dst: dst,
        })) {
            println!("channel send error: {e}");
            return;
        }
    }
}

pub fn init(
    ch_tx: mpsc::Sender<IpoedMsg>,
    wan_if_index: i32,
    lan_if_index: i32,
) -> Result<libc::c_int, String> {
    for if_index in [wan_if_index, lan_if_index] {
        let sockfd = utils::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM,
            (libc::ETH_P_IPV6 as u16).to_be() as i32,
        )?;

        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_IPV6 as u16).to_be();
        addr.sll_ifindex = if_index;
        utils::ll_bind(sockfd, &addr)?;
        utils::attach_icmp6_filter(sockfd)?;

        let ch_tx_tmp = ch_tx.clone();
        std::thread::spawn(move || {
            listener(sockfd, if_index, ch_tx_tmp);
        });
    }
    let sockfd = utils::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_ICMPV6)?;
    utils::set_ipv6_unicast_hops(sockfd, 255)?;
    utils::set_ipv6_multicast_hops(sockfd, 255)?;
    Ok(sockfd)
}
