// SPDX-License-Identifier: MIT
// Copyright(c) 2026 Masakazu Asama

use std::sync::mpsc;

mod packets;

mod common;
pub use common::*;

mod link;
pub use link::*;

mod addr;
pub use addr::*;

mod route;
pub use route::*;

#[cfg(test)]
mod tests;

use crate::IpoedMsg;

#[derive(Debug, Eq, PartialEq)]
pub enum RtnlMsg {
    WanLinkDown,
    WanLinkUp,
    LanLinkDown,
    LanLinkUp,
}

fn listener(rtnlsk: RtnlSocket, ch_tx: mpsc::Sender<IpoedMsg>, wanif: Link, lanif: Link) {
    let mut wanif = wanif;
    let mut lanif = lanif;
    loop {
        let links = match rtnlsk.read(
            |rtnl_msg, links| {
                if let packets::RtnlMsg::Link(link_msg) = rtnl_msg {
                    let if_type = IfType::from(link_msg.ifi_type);
                    let flags = IfiFlags::from(link_msg.ifi_flags);
                    links.push(Link {
                        if_type: if_type,
                        flags: flags,
                        index: link_msg.ifi_index,
                        ifname: link_msg.ifname,
                        address: link_msg.address,
                    });
                }
            },
            true,
        ) {
            Ok(links) => links,
            Err(e) => {
                println!("rtnl read error: {e}");
                return;
            }
        };
        for link in links {
            let mut msg: Option<RtnlMsg> = None;
            if link.index == wanif.index {
                if wanif.flags.has_up() && !link.flags.has_up() {
                    msg = Some(RtnlMsg::WanLinkDown);
                }
                if !wanif.flags.has_up() && link.flags.has_up() {
                    msg = Some(RtnlMsg::WanLinkUp);
                }
                wanif = link.clone();
            }
            if link.index == lanif.index {
                if lanif.flags.has_up() && !link.flags.has_up() {
                    msg = Some(RtnlMsg::LanLinkDown);
                }
                if !lanif.flags.has_up() && link.flags.has_up() {
                    msg = Some(RtnlMsg::LanLinkUp);
                }
                lanif = link.clone();
            }
            if let Some(msg) = msg {
                if let Err(e) = ch_tx.send(IpoedMsg::Rtnl(msg)) {
                    println!("channel send error: {e}");
                    return;
                }
            }
        }
    }
}

pub fn init(
    ch_tx: mpsc::Sender<IpoedMsg>,
    wan_if_index: i32,
    lan_if_index: i32,
) -> Result<(), String> {
    let mut wanif: Option<Link> = None;
    let mut lanif: Option<Link> = None;
    for link in dump_links()? {
        if link.index == wan_if_index {
            wanif = Some(link.clone());
        }
        if link.index == lan_if_index {
            lanif = Some(link.clone());
        }
    }
    let wanif = if let Some(wanif) = wanif {
        wanif
    } else {
        return Err(format!("WAN interface not found"));
    };
    let lanif = if let Some(lanif) = lanif {
        lanif
    } else {
        return Err(format!("LAN interface not found"));
    };
    let rtnlsk = RtnlSocket::new()?;
    let mut groups = GroupSet::new();
    let _ = groups.insert(Group::Link);
    rtnlsk.bind(groups)?;
    std::thread::spawn(move || {
        listener(rtnlsk, ch_tx, wanif, lanif);
    });
    Ok(())
}
