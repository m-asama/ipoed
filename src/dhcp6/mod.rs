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

const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr =
    Ipv6Addr::from_segments([0xff02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x2]);
const ALL_DHCP_SERVERS: Ipv6Addr =
    Ipv6Addr::from_segments([0xff05, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x3]);

const DHCPV6_CLIENT_PORT: u16 = 546;
const DHCPV6_SERVER_PORT: u16 = 547;

//pub const SOL_MAX_DELAY: u64 = 1000;
pub const SOL_TIMEOUT: u64 = 1000;
pub const SOL_MAX_RT: u64 = 3600000;
pub const REQ_TIMEOUT: u64 = 1000;
pub const REQ_MAX_RT: u64 = 30000;
pub const REQ_MAX_RC: usize = 10;
//pub const CNF_MAX_DELAY: u64 = 1000;
//pub const CNF_TIMEOUT: u64 = 1000;
//pub const CNF_MAX_RT: u64 = 4000;
//pub const CNF_MAX_RD: u64 = 10000;
pub const REN_TIMEOUT: u64 = 10000;
pub const REN_MAX_RT: u64 = 600000;
//pub const REB_TIMEOUT: u64 = 10000;
//pub const REB_MAX_RT: u64 = 600000;
//pub const INF_MAX_DELAY: u64 = 1000;
pub const INF_TIMEOUT: u64 = 1000;
pub const INF_MAX_RT: u64 = 3600000;
//pub const REL_TIMEOUT: u64 = 1000;
//pub const REL_MAX_RC: usize = 4;
//pub const DEC_TIMEOUT: u64 = 1000;
//pub const DEC_MAX_RC: usize = 4;
//pub const REC_TIMEOUT: u64 = 2000;
//pub const REC_MAX_RC: usize = 8;
//pub const HOP_COUNT_LIMIT: usize = 8;
//pub const IRT_DEFAULT: u64 = 86400000;
//pub const IRT_MINIMUM: u64 = 600000;
//pub const MAX_WAIT_TIME: u64 = 60000;

#[derive(Debug, Eq, PartialEq)]
pub struct Dhcp6Pkt {
    pub msg: packets::Dhcp6Msg,
    pub iif: Option<i32>,
    pub src: Option<Ipv6Addr>,
    pub dst: Option<Ipv6Addr>,
}

pub fn send_sol(
    sk: libc::c_int,
    oif: i32,
    src_hwaddr: [u8; 6],
    src_lladdr: &Ipv6Addr,
    transaction_id: u32,
    elapsed_time: u16,
    ia_pd: bool,
) -> Result<(), String> {
    let client_id = Some(packets::ClientIdOpt {
        duid: packets::Duid::Ll(packets::LlDuid {
            ll_addr: src_hwaddr,
        }),
    });
    let mut ia_pds = Vec::<packets::IaPdOpt>::new();
    if ia_pd {
        ia_pds.push(packets::IaPdOpt {
            iaid: [0; 4],
            t1: 0,
            t2: 0,
            ia_prefixes: Vec::<packets::IaPrefixOpt>::new(),
            status_code: None,
            unknown_opts: Vec::<packets::Dhcp6Opt>::new(),
        });
    }
    let elapsed_time = Some(packets::ElapsedTimeOpt {
        elapsed_time: elapsed_time,
    });
    let reconf_accept = Some(packets::ReconfAcceptOpt {});
    let msg = packets::SolicitMsg {
        transaction_id: transaction_id,
        client_id: client_id,
        ia_nas: Vec::<packets::IaNaOpt>::new(),
        ia_pds: ia_pds,
        opt_req: None,
        elapsed_time: elapsed_time,
        rapid_commit: None,
        user_class: None,
        vendor_classes: Vec::<packets::VendorClassOpt>::new(),
        vendor_infos: Vec::<packets::VendorInfoOpt>::new(),
        reconf_accept: reconf_accept,
        unknown_opts: Vec::<packets::Dhcp6Opt>::new(),
    };
    let mut buf = [0u8; 2048];
    let n = match msg.serialize(&mut buf) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    match utils::ipv6_sendmsg(
        sk,
        &mut buf[..n],
        Some(oif),
        Some(src_lladdr),
        &ALL_DHCP_RELAY_AGENTS_AND_SERVERS,
        DHCPV6_SERVER_PORT,
    ) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    Ok(())
}

pub fn send_req(
    sk: libc::c_int,
    oif: i32,
    src_hwaddr: [u8; 6],
    src_lladdr: &Ipv6Addr,
    transaction_id: u32,
    elapsed_time: u16,
    server_id: &Option<ServerIdOpt>,
    ia_prefixes: &Vec<packets::IaPrefixOpt>,
) -> Result<(), String> {
    let client_id = Some(packets::ClientIdOpt {
        duid: packets::Duid::Ll(packets::LlDuid {
            ll_addr: src_hwaddr,
        }),
    });
    let mut ia_pds = Vec::<packets::IaPdOpt>::new();
    if ia_prefixes.len() > 0 {
        ia_pds.push(packets::IaPdOpt {
            iaid: [0; 4],
            t1: 0,
            t2: 0,
            ia_prefixes: ia_prefixes.to_vec(),
            status_code: None,
            unknown_opts: Vec::<packets::Dhcp6Opt>::new(),
        });
    }
    let elapsed_time = Some(packets::ElapsedTimeOpt {
        elapsed_time: elapsed_time,
    });
    let reconf_accept = Some(packets::ReconfAcceptOpt {});
    let msg = packets::RequestMsg {
        transaction_id: transaction_id,
        client_id: client_id,
        server_id: server_id.clone(),
        ia_nas: Vec::<packets::IaNaOpt>::new(),
        ia_pds: ia_pds,
        opt_req: Some(OptReqOpt {
            requested_opt_codes: vec![packets::DnsRecursiveNameServerOpt::OPT_CODE],
        }),
        elapsed_time: elapsed_time,
        user_class: None,
        vendor_classes: Vec::<packets::VendorClassOpt>::new(),
        vendor_infos: Vec::<packets::VendorInfoOpt>::new(),
        reconf_accept: reconf_accept,
        unknown_opts: Vec::<packets::Dhcp6Opt>::new(),
    };
    let mut buf = [0u8; 2048];
    let n = match msg.serialize(&mut buf) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    match utils::ipv6_sendmsg(
        sk,
        &mut buf[..n],
        Some(oif),
        Some(src_lladdr),
        &ALL_DHCP_RELAY_AGENTS_AND_SERVERS,
        DHCPV6_SERVER_PORT,
    ) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    Ok(())
}

pub fn send_ren(
    sk: libc::c_int,
    oif: i32,
    src_hwaddr: [u8; 6],
    src_lladdr: &Ipv6Addr,
    transaction_id: u32,
    elapsed_time: u16,
    server_id: &Option<ServerIdOpt>,
    ia_prefixes: &Vec<packets::IaPrefixOpt>,
) -> Result<(), String> {
    let client_id = Some(packets::ClientIdOpt {
        duid: packets::Duid::Ll(packets::LlDuid {
            ll_addr: src_hwaddr,
        }),
    });
    let mut ia_pds = Vec::<packets::IaPdOpt>::new();
    if ia_prefixes.len() > 0 {
        ia_pds.push(packets::IaPdOpt {
            iaid: [0; 4],
            t1: 0,
            t2: 0,
            ia_prefixes: ia_prefixes.to_vec(),
            status_code: None,
            unknown_opts: Vec::<packets::Dhcp6Opt>::new(),
        });
    }
    let elapsed_time = Some(packets::ElapsedTimeOpt {
        elapsed_time: elapsed_time,
    });
    let reconf_accept = Some(packets::ReconfAcceptOpt {});
    let msg = packets::RenewMsg {
        transaction_id: transaction_id,
        client_id: client_id,
        server_id: server_id.clone(),
        ia_nas: Vec::<packets::IaNaOpt>::new(),
        ia_pds: ia_pds,
        opt_req: Some(OptReqOpt {
            requested_opt_codes: vec![packets::DnsRecursiveNameServerOpt::OPT_CODE],
        }),
        elapsed_time: elapsed_time,
        user_class: None,
        vendor_classes: Vec::<packets::VendorClassOpt>::new(),
        vendor_infos: Vec::<packets::VendorInfoOpt>::new(),
        reconf_accept: reconf_accept,
        unknown_opts: Vec::<packets::Dhcp6Opt>::new(),
    };
    let mut buf = [0u8; 2048];
    let n = match msg.serialize(&mut buf) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    match utils::ipv6_sendmsg(
        sk,
        &mut buf[..n],
        Some(oif),
        Some(src_lladdr),
        &ALL_DHCP_RELAY_AGENTS_AND_SERVERS,
        DHCPV6_SERVER_PORT,
    ) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    Ok(())
}

pub fn send_rep(
    sk: libc::c_int,
    oif: i32,
    src_hwaddr: [u8; 6],
    src_lladdr: &Ipv6Addr,
    transaction_id: u32,
    dst_addr: &Ipv6Addr,
    client_id: &Option<packets::ClientIdOpt>,
    dns_servers: &Vec<Ipv6Addr>,
    dns_searchs: &Vec<String>,
) -> Result<(), String> {
    let server_id = Some(packets::ServerIdOpt {
        duid: packets::Duid::Ll(packets::LlDuid {
            ll_addr: src_hwaddr,
        }),
    });
    let dns_recursive_name_server = Some(packets::DnsRecursiveNameServerOpt {
        dns_recursive_name_servers: dns_servers.clone(),
    });
    let domain_search_list = Some(packets::DomainSearchListOpt {
        searchs: dns_searchs.clone(),
    });
    let reconf_accept = Some(packets::ReconfAcceptOpt {});
    let msg = packets::ReplyMsg {
        transaction_id: transaction_id,
        client_id: client_id.clone(),
        server_id: server_id,
        ia_nas: Vec::<IaNaOpt>::new(),
        ia_pds: Vec::<IaPdOpt>::new(),
        auth: None,
        status_code: None,
        rapid_commit: None,
        user_class: None,
        vendor_classes: Vec::<packets::VendorClassOpt>::new(),
        vendor_infos: Vec::<packets::VendorInfoOpt>::new(),
        reconf_accept: reconf_accept,
        info_refresh_time: None,
        sol_max_rt: None,
        inf_max_rt: None,
        dns_recursive_name_server: dns_recursive_name_server,
        domain_search_list: domain_search_list,
        unknown_opts: Vec::<packets::Dhcp6Opt>::new(),
    };
    let mut buf = [0u8; 2048];
    let n = match msg.serialize(&mut buf) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    match utils::ipv6_sendmsg(
        sk,
        &mut buf[..n],
        Some(oif),
        Some(src_lladdr),
        dst_addr,
        DHCPV6_CLIENT_PORT,
    ) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    Ok(())
}

pub fn send_inf(
    sk: libc::c_int,
    oif: i32,
    src_hwaddr: [u8; 6],
    src_lladdr: &Ipv6Addr,
    transaction_id: u32,
    elapsed_time: u16,
) -> Result<(), String> {
    let client_id = Some(packets::ClientIdOpt {
        duid: packets::Duid::Ll(packets::LlDuid {
            ll_addr: src_hwaddr,
        }),
    });
    let elapsed_time = Some(packets::ElapsedTimeOpt {
        elapsed_time: elapsed_time,
    });
    let reconf_accept = Some(packets::ReconfAcceptOpt {});
    let msg = packets::InfoReqMsg {
        transaction_id: transaction_id,
        client_id: client_id,
        server_id: None,
        opt_req: Some(OptReqOpt {
            requested_opt_codes: vec![packets::DnsRecursiveNameServerOpt::OPT_CODE],
        }),
        elapsed_time: elapsed_time,
        user_class: None,
        vendor_classes: Vec::<packets::VendorClassOpt>::new(),
        vendor_infos: Vec::<packets::VendorInfoOpt>::new(),
        reconf_accept: reconf_accept,
        unknown_opts: Vec::<packets::Dhcp6Opt>::new(),
    };
    let mut buf = [0u8; 2048];
    let n = match msg.serialize(&mut buf) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    match utils::ipv6_sendmsg(
        sk,
        &mut buf[..n],
        Some(oif),
        Some(src_lladdr),
        &ALL_DHCP_RELAY_AGENTS_AND_SERVERS,
        DHCPV6_SERVER_PORT,
    ) {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    Ok(())
}

fn listener(sockfd: libc::c_int, ch_tx: mpsc::Sender<IpoedMsg>) {
    loop {
        let mut buf = [0u8; 8192];
        let mut iif: Option<i32> = None;
        let mut src: Option<Ipv6Addr> = None;
        let mut dst: Option<Ipv6Addr> = None;
        let n = match utils::ipv6_recvmsg(sockfd, &mut buf, &mut iif, &mut src, &mut dst) {
            Ok(n) => n,
            Err(e) => {
                println!("ipv6_recvmsg error: {e}");
                return;
            }
        };
        let msg = match packets::Dhcp6Msg::parse(&buf[0..n]) {
            Ok(msg) => msg,
            Err(e) => {
                println!("dhcp6 parse error: {e}");
                continue;
            }
        };
        if let Err(e) = ch_tx.send(IpoedMsg::Dhcp6(Dhcp6Pkt {
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

fn init1(ch_tx: mpsc::Sender<IpoedMsg>, port: u16) -> Result<libc::c_int, String> {
    let sockfd = utils::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0)?;
    utils::set_ipv6_recvpktinfo(sockfd)?;
    utils::set_ipv6_v6only(sockfd)?;
    let addr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: libc::htons(port),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr { s6_addr: [0u8; 16] },
        sin6_scope_id: 0,
    };
    utils::ipv6_bind(sockfd, &addr)?;
    std::thread::spawn(move || {
        listener(sockfd, ch_tx);
    });
    Ok(sockfd)
}

pub fn init(
    ch_tx: mpsc::Sender<IpoedMsg>,
    lan_if_index: i32,
) -> Result<(libc::c_int, libc::c_int), String> {
    let ch_tx_dhcp6s = ch_tx.clone();
    let ch_tx_dhcp6c = ch_tx;
    let sk_dhcp6s = init1(ch_tx_dhcp6s, DHCPV6_SERVER_PORT)?;
    let sk_dhcp6c = init1(ch_tx_dhcp6c, DHCPV6_CLIENT_PORT)?;
    utils::set_ipv6_add_membership(sk_dhcp6s, &ALL_DHCP_RELAY_AGENTS_AND_SERVERS, lan_if_index)?;
    utils::set_ipv6_add_membership(sk_dhcp6s, &ALL_DHCP_SERVERS, lan_if_index)?;
    Ok((sk_dhcp6s, sk_dhcp6c))
}
