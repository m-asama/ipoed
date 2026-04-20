// SPDX-License-Identifier: MIT
// Copyright(c) 2026 Masakazu Asama

use std::net::Ipv6Addr;

mod packets;
pub use packets::*;

pub fn ipv6_forwarding(if_name: &str) -> bool {
    let path = format!("/proc/sys/net/ipv6/conf/{if_name}/forwarding");
    if let Ok(s) = std::fs::read_to_string(&path) {
        if s == "1\n" {
            return true;
        }
    }
    false
}

pub fn ipv6_address(prefix: &Ipv6Addr, iid: &Ipv6Addr) -> Ipv6Addr {
    let prefix_segs = prefix.segments();
    let iid_segs = iid.segments();
    Ipv6Addr::new(
        prefix_segs[0],
        prefix_segs[1],
        prefix_segs[2],
        prefix_segs[3],
        iid_segs[4],
        iid_segs[5],
        iid_segs[6],
        iid_segs[7],
    )
}

pub fn ipv6_ll_addr(hw_addr: &[u8; 6]) -> Ipv6Addr {
    let mut octs = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xfe, 0, 0, 0];
    octs[8..11].copy_from_slice(&hw_addr[0..3]);
    octs[13..16].copy_from_slice(&hw_addr[3..6]);
    octs[8] ^= 2;
    Ipv6Addr::from_octets(octs)
}

pub fn resolved_conf_update(servers: &[Ipv6Addr], searchs: &[String]) {
    let mut buf = String::new();
    buf += "[Resolve]\n";
    buf += "DNS=";
    for server in servers {
        buf += &format!(" {}", server);
    }
    buf += "\n";
    buf += "Domains=";
    for search in searchs {
        buf += &format!(" {}", search);
    }
    buf += "\n";
    if let Err(e) = std::fs::write("/etc/systemd/resolved.conf.d/ipoed.conf", &buf) {
        println!("resolved conf update error: {e}");
    }
    if let Err(e) = std::process::Command::new("systemctl")
        .arg("restart")
        .arg("systemd-resolved.service")
        .status()
    {
        println!("systemctl restart systemd-resolved.service error: {e}");
    }
}

pub fn socket(
    dom: libc::c_int,
    ty: libc::c_int,
    proto: libc::c_int,
) -> Result<libc::c_int, String> {
    let ret = unsafe { libc::socket(dom, ty, proto) };
    if ret >= 0 {
        Ok(ret)
    } else {
        Err(format!("socket open failed"))
    }
}

pub fn ll_bind(sk: libc::c_int, addr: &libc::sockaddr_ll) -> Result<(), String> {
    let ret = unsafe {
        libc::bind(
            sk,
            addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(format!("bind failed"))
    }
}

pub fn attach_icmp6_filter(sockfd: libc::c_int) -> Result<(), String> {
    let mut code: [libc::sock_filter; 9] = [
        libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_B | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 6,
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 5,
            k: libc::IPPROTO_ICMPV6 as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_B | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 40,
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 4,
            jf: 0,
            k: 133,
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 3,
            jf: 0,
            k: 134,
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 2,
            jf: 0,
            k: 135,
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 1,
            jf: 0,
            k: 136,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        }, // reject
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: u32::MAX,
        }, // accept
    ];
    let prog = libc::sock_fprog {
        len: code.len() as u16,
        filter: code.as_mut_ptr(),
    };
    let ret = unsafe {
        libc::setsockopt(
            sockfd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &prog as *const _ as *const libc::c_void,
            size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(format!("setsockopt SO_ATTACH_FILTER failed"));
    }
    Ok(())
}

pub fn ipv6_bind(sk: libc::c_int, addr: &libc::sockaddr_in6) -> Result<(), String> {
    let ret = unsafe {
        libc::bind(
            sk,
            addr as *const libc::sockaddr_in6 as *const libc::sockaddr,
            size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(format!("bind failed"))
    }
}

pub fn set_ipv6_add_membership(sk: libc::c_int, maddr: &Ipv6Addr, iif: i32) -> Result<(), String> {
    let level = libc::IPPROTO_IPV6;
    let name = libc::IPV6_ADD_MEMBERSHIP;
    let maddr_tmp = libc::in6_addr {
        s6_addr: maddr.octets(),
    };
    let val = libc::ipv6_mreq {
        ipv6mr_multiaddr: maddr_tmp,
        ipv6mr_interface: iif as libc::c_uint,
    };
    let valp = &val as *const libc::ipv6_mreq as *const libc::c_void;
    let len: libc::socklen_t = std::mem::size_of::<libc::ipv6_mreq>() as u32;
    let ret = unsafe { libc::setsockopt(sk, level, name, valp, len) };
    if ret == 0 {
        Ok(())
    } else {
        Err(format!("setsockopt failed"))
    }
}

pub fn set_ipv6_unicast_hops(sk: libc::c_int, val: i32) -> Result<(), String> {
    let level = libc::IPPROTO_IPV6;
    let name = libc::IPV6_UNICAST_HOPS;
    let valp = &val as *const libc::c_int as *const libc::c_void;
    let len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as u32;
    let ret = unsafe { libc::setsockopt(sk, level, name, valp, len) };
    if ret == 0 {
        Ok(())
    } else {
        Err(format!("setsockopt failed"))
    }
}

pub fn set_ipv6_multicast_hops(sk: libc::c_int, val: i32) -> Result<(), String> {
    let level = libc::IPPROTO_IPV6;
    let name = libc::IPV6_MULTICAST_HOPS;
    let valp = &val as *const libc::c_int as *const libc::c_void;
    let len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as u32;
    let ret = unsafe { libc::setsockopt(sk, level, name, valp, len) };
    if ret == 0 {
        Ok(())
    } else {
        Err(format!("setsockopt failed"))
    }
}

/*
pub fn set_ipv6_multicast_if(sk: libc::c_int, oif: i32) -> Result<(), String> {
    let level = libc::IPPROTO_IPV6;
    let name = libc::IPV6_MULTICAST_IF;
    let valp = &oif as *const libc::c_int as *const libc::c_void;
    let len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as u32;
    let ret = unsafe { libc::setsockopt(sk, level, name, valp, len) };
    if ret == 0 {
        Ok(())
    } else {
        Err(format!("setsockopt failed"))
    }
}
 */

pub fn set_ipv6_recvpktinfo(sk: libc::c_int) -> Result<(), String> {
    let level = libc::IPPROTO_IPV6;
    let name = libc::IPV6_RECVPKTINFO;
    let val: libc::c_int = 1;
    let valp = &val as *const libc::c_int as *const libc::c_void;
    let len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as u32;
    let ret = unsafe { libc::setsockopt(sk, level, name, valp, len) };
    if ret == 0 {
        Ok(())
    } else {
        Err(format!("setsockopt failed"))
    }
}

pub fn set_ipv6_v6only(sk: libc::c_int) -> Result<(), String> {
    let level = libc::IPPROTO_IPV6;
    let name = libc::IPV6_V6ONLY;
    let val: libc::c_int = 1;
    let valp = &val as *const libc::c_int as *const libc::c_void;
    let len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as u32;
    let ret = unsafe { libc::setsockopt(sk, level, name, valp, len) };
    if ret == 0 {
        Ok(())
    } else {
        Err(format!("setsockopt failed"))
    }
}

pub fn parse_cmsg(bytes: &[u8]) -> Result<Vec<Cmsg>, String> {
    let mut cmsgs = Vec::<Cmsg>::new();
    let mut pos = 0;
    while pos < bytes.len() {
        if bytes.len() < pos + 8 {
            return Err(format!("Too short message"));
        }
        let cmsg_len = u64::from_ne_bytes(bytes[pos..pos + 8].try_into().unwrap()) as usize;
        if cmsg_len == 0 {
            break;
        }
        if bytes.len() < pos + cmsg_len {
            return Err(format!("Invalid cmsg length"));
        }
        cmsgs.push(Cmsg::parse(&bytes[pos..pos + cmsg_len])?);
        pos += unsafe { libc::CMSG_SPACE(cmsg_len as u32) as usize };
    }
    Ok(cmsgs)
}

pub fn ipv6_sendmsg(
    sk: libc::c_int,
    buf: &mut [u8],
    oif: Option<i32>,
    src: Option<&Ipv6Addr>,
    daddr: &Ipv6Addr,
    dport: u16,
) -> Result<usize, String> {
    let mut cbuf = [0u64; 128];
    let mut msg_iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut msg_name = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: libc::htons(dport),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: daddr.octets(),
        },
        sin6_scope_id: 0,
    };
    let mut msg = libc::msghdr {
        msg_name: &mut msg_name as *mut libc::sockaddr_in6 as *mut libc::c_void,
        msg_namelen: size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        msg_iov: &mut msg_iov,
        msg_iovlen: 1,
        msg_control: cbuf.as_mut_ptr() as *mut libc::c_void,
        msg_controllen: cbuf.len(),
        msg_flags: 0,
    };
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        let cmsg_len = libc::CMSG_LEN(size_of::<libc::in6_pktinfo>() as libc::c_uint);
        (*cmsg).cmsg_len = cmsg_len as libc::size_t;
        (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
        (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
        let pktinfo = libc::CMSG_DATA(cmsg) as *mut libc::in6_pktinfo;
        if let Some(src) = src {
            (*pktinfo).ipi6_addr = libc::in6_addr {
                s6_addr: src.octets(),
            };
        }
        if let Some(oif) = oif {
            (*pktinfo).ipi6_ifindex = oif as u32;
        }
    }
    msg.msg_controllen = size_of::<libc::cmsghdr>() + size_of::<libc::in6_pktinfo>();
    let n = unsafe { libc::sendmsg(sk, &msg, 0) };
    if n <= 0 {
        return Err(format!("sendmsg error: {n}"));
    }
    let ret = n as usize;
    Ok(ret as usize)
}

pub fn ipv6_recvmsg(
    sk: libc::c_int,
    buf: &mut [u8],
    iif: &mut Option<i32>,
    src: &mut Option<Ipv6Addr>,
    dst: &mut Option<Ipv6Addr>,
) -> Result<usize, String> {
    let mut addr = libc::sockaddr_in6 {
        sin6_family: 0,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr { s6_addr: [0u8; 16] },
        sin6_scope_id: 0,
    };
    let iov_base = buf as *mut [u8] as *mut libc::c_void;
    let iov_len = buf.len();
    let mut iov = libc::iovec {
        iov_base: iov_base,
        iov_len: iov_len,
    };
    let mut cmsgbuf = [0u8; 1024];
    let msg_name = &mut addr as *mut libc::sockaddr_in6 as *mut libc::c_void;
    let msg_namelen: u32 = std::mem::size_of::<libc::sockaddr_in6>() as u32;
    let msg_iov = &mut iov as *mut libc::iovec;
    let msg_iovlen = 1;
    let msg_control = &mut cmsgbuf as *mut [u8] as *mut libc::c_void;
    let msg_controllen = cmsgbuf.len();
    let mut msg = libc::msghdr {
        msg_name: msg_name,
        msg_namelen: msg_namelen,
        msg_iov: msg_iov,
        msg_iovlen: msg_iovlen,
        msg_control: msg_control,
        msg_controllen: msg_controllen,
        msg_flags: 0,
    };
    let msg = &mut msg as *mut libc::msghdr;
    let n = unsafe { libc::recvmsg(sk, msg, 0) };
    if n < 0 {
        return Err(format!("recvmsg error: {n}"));
    }
    if addr.sin6_addr.s6_addr != [0u8; 16] {
        *src = Some(Ipv6Addr::from_octets(addr.sin6_addr.s6_addr));
    }
    if let Ok(cmsgs) = parse_cmsg(&cmsgbuf) {
        for cmsg in cmsgs {
            if let Cmsg::Ipv6Pktinfo(pktinfo) = cmsg {
                *dst = Some(pktinfo.ipi6_addr);
                *iif = Some(pktinfo.ipi6_ifindex);
            }
        }
    }
    let ret = n as usize;
    Ok(ret)
}
