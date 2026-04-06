// SPDX-License-Identifier: MIT
// Copyright(c) 2026 Masakazu Asama

use std::net::Ipv6Addr;

use crate::icmp6;

#[test]
fn prefix_flags() -> Result<(), String> {
    let mut prefix_flags = icmp6::packets::PrefixFlags::from(0u8);
    if prefix_flags.has_on_link() {
        return Err(format!(""));
    }
    if prefix_flags.has_autonomous_addr_conf() {
        return Err(format!(""));
    }
    if !prefix_flags.set_on_link() {
        return Err(format!(""));
    }
    if !prefix_flags.set_autonomous_addr_conf() {
        return Err(format!(""));
    }
    if !prefix_flags.has_on_link() {
        return Err(format!(""));
    }
    if !prefix_flags.has_autonomous_addr_conf() {
        return Err(format!(""));
    }
    if !prefix_flags.unset_on_link() {
        return Err(format!(""));
    }
    if !prefix_flags.unset_autonomous_addr_conf() {
        return Err(format!(""));
    }
    if prefix_flags.has_on_link() {
        return Err(format!(""));
    }
    if prefix_flags.has_autonomous_addr_conf() {
        return Err(format!(""));
    }
    Ok(())
}

#[test]
fn ra_flags() -> Result<(), String> {
    let mut ra_flags = icmp6::packets::RaFlags::from(0u8);
    if ra_flags.has_managed_addr_config() {
        return Err(format!(""));
    }
    if ra_flags.has_other_config() {
        return Err(format!(""));
    }
    if !ra_flags.set_managed_addr_config() {
        return Err(format!(""));
    }
    if !ra_flags.set_other_config() {
        return Err(format!(""));
    }
    if !ra_flags.has_managed_addr_config() {
        return Err(format!(""));
    }
    if !ra_flags.has_other_config() {
        return Err(format!(""));
    }
    if !ra_flags.unset_managed_addr_config() {
        return Err(format!(""));
    }
    if !ra_flags.unset_other_config() {
        return Err(format!(""));
    }
    if ra_flags.has_managed_addr_config() {
        return Err(format!(""));
    }
    if ra_flags.has_other_config() {
        return Err(format!(""));
    }
    Ok(())
}

#[test]
fn na_flags() -> Result<(), String> {
    let mut na_flags = icmp6::packets::NaFlags::from(0u32);
    if na_flags.has_router() {
        return Err(format!(""));
    }
    if na_flags.has_solicited() {
        return Err(format!(""));
    }
    if na_flags.has_override() {
        return Err(format!(""));
    }
    if !na_flags.set_router() {
        return Err(format!(""));
    }
    if !na_flags.set_solicited() {
        return Err(format!(""));
    }
    if !na_flags.set_override() {
        return Err(format!(""));
    }
    if !na_flags.has_router() {
        return Err(format!(""));
    }
    if !na_flags.has_solicited() {
        return Err(format!(""));
    }
    if !na_flags.has_override() {
        return Err(format!(""));
    }
    if !na_flags.unset_router() {
        return Err(format!(""));
    }
    if !na_flags.unset_solicited() {
        return Err(format!(""));
    }
    if !na_flags.unset_override() {
        return Err(format!(""));
    }
    if na_flags.has_router() {
        return Err(format!(""));
    }
    if na_flags.has_solicited() {
        return Err(format!(""));
    }
    if na_flags.has_override() {
        return Err(format!(""));
    }
    Ok(())
}

#[test]
fn rs() -> Result<(), String> {
    let orgraw = [
        0x85, // Type
        0x00, // Code
        0x00, 0x00, // Checksum
        0x00, 0x00, 0x00, 0x00, // Reserved
        0x01, 0x01, 0x52, 0x54, 0x00, 0x52, 0x86, 0x52,
    ];
    let orgmsg = icmp6::packets::RtSolicitMsg {
        src_lladdr: Some(icmp6::packets::SrcLLAddrOpt {
            src_lladdr: [0x52, 0x54, 0x0, 0x52, 0x86, 0x52],
        }),
    };
    let resmsg = match icmp6::packets::RtSolicitMsg::parse(&orgraw) {
        Ok(resmsg) => resmsg,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resmsg: {:?}", resmsg);
    println!("orgmsg: {:?}", orgmsg);
    if resmsg != orgmsg {
        return Err(format!("resmsg not eq"));
    }
    let mut resraw = [0u8; 16];
    if let Err(e) = resmsg.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn ra() -> Result<(), String> {
    let orgraw = [
        0x86, // Type
        0x00, // Code
        0x00, 0x00, // Checksum
        0x40, // Cur Hop Limit
        0x40, // MO flags
        0x07, 0x08, // Router Lifetime
        0x00, 0x04, 0x93, 0xe0, // Reachable Time
        0x00, 0x00, 0x27, 0x10, // Retrans Timer
        0x01, 0x01, 0x88, 0x43, 0xe1, 0x01, 0xd6, 0xc5, // Source Link-layer Address
        0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc, // MTU
        0x03, 0x04, // Prefix Information
        0x40, // Prefix Length
        0xc0, // LA flags
        0x00, 0x27, 0x8d, 0x00, // Valid Lifetime
        0x00, 0x09, 0x3a, 0x80, // Preferred Lifetime
        0x00, 0x00, 0x00, 0x00, // Reserved2
        0x24, 0x00, 0x24, 0x12, 0x8d, 0x01, 0xc8, 0x00, // Prefix
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let orgmsg = icmp6::packets::RtAdvertMsg {
        cur_hop_limit: 64,
        flags: icmp6::packets::RaFlags::from(0x40u8),
        router_lifetime: 1800,
        reachable_time: 300000,
        retrans_timer: 10000,
        src_lladdr: Some(icmp6::packets::SrcLLAddrOpt {
            src_lladdr: [0x88, 0x43, 0xe1, 0x01, 0xd6, 0xc5],
        }),
        mtu: Some(icmp6::packets::MtuOpt { mtu: 1500 }),
        prefix_infos: vec![icmp6::packets::PrefixInfoOpt {
            prefix_len: 64,
            flags: icmp6::packets::PrefixFlags::from(0xc0u8),
            valid_lifetime: 2592000,
            preferred_lifetime: 604800,
            prefix: Ipv6Addr::from_octets([
                0x24, 0x00, 0x24, 0x12, 0x8d, 0x01, 0xc8, 0x00, //
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]),
        }],
    };
    let resmsg = match icmp6::packets::RtAdvertMsg::parse(&orgraw) {
        Ok(resmsg) => resmsg,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resmsg: {:?}", resmsg);
    println!("orgmsg: {:?}", orgmsg);
    if resmsg != orgmsg {
        return Err(format!("resmsg not eq"));
    }
    let mut resraw = [0u8; 64];
    if let Err(e) = resmsg.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn ns() -> Result<(), String> {
    let orgraw = [
        0x87, // Type
        0x00, // Code
        0x00, 0x00, // Checksum
        0x00, 0x00, 0x00, 0x00, // Reserved
        0x24, 0x06, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x03, // Target Address
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Target Address
        0x01, 0x01, 0x00, 0x0d, 0xb9, 0x57, 0x02, 0x55, // Source link-layer address
    ];
    let orgmsg = icmp6::packets::NeighSolicitMsg {
        tgt_addr: Ipv6Addr::from_octets([
            0x24, 0x06, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x03, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        ]),
        src_lladdr: Some(icmp6::packets::SrcLLAddrOpt {
            src_lladdr: [0x00, 0x0d, 0xb9, 0x57, 0x02, 0x55],
        }),
    };
    let resmsg = match icmp6::packets::NeighSolicitMsg::parse(&orgraw) {
        Ok(resmsg) => resmsg,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resmsg: {:?}", resmsg);
    println!("orgmsg: {:?}", orgmsg);
    if resmsg != orgmsg {
        return Err(format!("resmsg not eq"));
    }
    let mut resraw = [0u8; 32];
    if let Err(e) = resmsg.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn na() -> Result<(), String> {
    let orgraw = [
        0x88, // Type
        0x00, // Code
        0x00, 0x00, // Checksum
        0x60, 0x00, 0x00, 0x00, // RSO flags
        0x24, 0x06, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x03, // Target Address
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Target Address
        0x02, 0x01, 0x00, 0x22, 0x64, 0x06, 0xe8, 0x38, // Target link-layer address
    ];
    let orgmsg = icmp6::packets::NeighAdvertMsg {
        flags: icmp6::packets::NaFlags::from(0x60000000u32),
        tgt_addr: Ipv6Addr::from_octets([
            0x24, 0x06, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x03, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        ]),
        tgt_lladdr: Some(icmp6::packets::TgtLLAddrOpt {
            tgt_lladdr: [0x00, 0x22, 0x64, 0x06, 0xe8, 0x38],
        }),
    };
    let resmsg = match icmp6::packets::NeighAdvertMsg::parse(&orgraw) {
        Ok(resmsg) => resmsg,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resmsg: {:?}", resmsg);
    println!("orgmsg: {:?}", orgmsg);
    if resmsg != orgmsg {
        return Err(format!("resmsg not eq"));
    }
    let mut resraw = [0u8; 32];
    if let Err(e) = resmsg.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn redire() -> Result<(), String> {
    let orgraw = [
        0x89, // Type
        0x00, // Code
        0x00, 0x00, //Checksum
        0x00, 0x00, 0x00, 0x00, // Reserved
        0x24, 0x06, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x03, // Target Address
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Target Address
        0x24, 0x06, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x03, // Destination Address
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Destination Address
        0x02, 0x01, 0x00, 0x22, 0x64, 0x06, 0xe8, 0x38, // Target link-layer address
        0x04, // Type: Redirected Header
        0x06, // Length
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
        0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0x24, 0x06, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x7c, 0x6d, 0xf3, 0xff, 0xfe, 0x85, 0xe9, 0x75,
    ];
    let orgmsg = icmp6::packets::RedirectMsg {
        tgt_addr: Ipv6Addr::from_octets([
            0x24, 0x06, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x03, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        ]),
        dst_addr: Ipv6Addr::from_octets([
            0x24, 0x06, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x03, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]),
        tgt_lladdr: Some(icmp6::packets::TgtLLAddrOpt {
            tgt_lladdr: [0x00, 0x22, 0x64, 0x06, 0xe8, 0x38],
        }),
        redirected_hdr: Some(icmp6::packets::RedirectedHdrOpt {
            iphdr_data: vec![
                0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0x24, 0x06, 0xb8, 0x00, 0x00, 0x00,
                0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xfe, 0x80, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x7c, 0x6d, 0xf3, 0xff, 0xfe, 0x85, 0xe9, 0x75,
            ],
        }),
    };
    let resmsg = match icmp6::packets::RedirectMsg::parse(&orgraw) {
        Ok(resmsg) => resmsg,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    println!("resmsg: {:?}", resmsg);
    println!("orgmsg: {:?}", orgmsg);
    if resmsg != orgmsg {
        return Err(format!("resmsg not eq"));
    }
    let mut resraw = [0u8; 96];
    if let Err(e) = resmsg.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    println!("resraw: {:?}", resraw);
    println!("orgraw: {:?}", orgraw);
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}

#[test]
fn icmp6() -> Result<(), String> {
    let orgraw = [
        0x89, // Type
        0x00, // Code
        0x00, 0x00, //Checksum
        0x00, 0x00, 0x00, 0x00, // Reserved
        0x24, 0x06, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x03, // Target Address
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Target Address
        0x24, 0x06, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x03, // Destination Address
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Destination Address
        0x02, 0x01, 0x00, 0x22, 0x64, 0x06, 0xe8, 0x38, // Target link-layer address
        0x04, // Type: Redirected Header
        0x06, // Length
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
        0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0x24, 0x06, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x7c, 0x6d, 0xf3, 0xff, 0xfe, 0x85, 0xe9, 0x75,
    ];
    let resmsg = match icmp6::packets::Icmp6Msg::parse(&orgraw) {
        Ok(resmsg) => resmsg,
        Err(e) => return Err(format!("parse error {}", e)),
    };
    let mut resraw = [0u8; 96];
    if let Err(e) = resmsg.serialize(&mut resraw) {
        return Err(format!("serialize error {}", e));
    };
    if resraw != orgraw {
        return Err(format!("resraw not eq"));
    }
    Ok(())
}
