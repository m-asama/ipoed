// SPDX-License-Identifier: MIT
// Copyright(c) 2026 Masakazu Asama

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::mpsc;

use crate::IpoedMsg;

#[derive(Debug)]
pub enum HookEvent {
    Ipv6Up,
    Ipv6Down,
    Ipv4Up,
    Ipv4Down,
}

impl HookEvent {
    fn as_str(&self) -> &str {
        match self {
            HookEvent::Ipv6Up => "IPV6_UP",
            HookEvent::Ipv6Down => "IPV6_DOWN",
            HookEvent::Ipv4Up => "IPV4_UP",
            HookEvent::Ipv4Down => "IPV4_DOWN",
        }
    }
}

#[derive(Debug)]
pub struct HookReq {
    pub path: String,
    pub event: HookEvent,
    pub wan_if: String,
    pub lan_if: String,
    pub ipv4_addr: Option<Ipv4Addr>,
    pub ipv6_addr: Option<Ipv6Addr>,
}

fn hook(_ch_tx: mpsc::Sender<IpoedMsg>, req_rx: mpsc::Receiver<HookReq>) {
    while let Ok(req) = req_rx.recv() {
        let path = std::path::Path::new(&req.path);
        if !path.exists() {
            println!("Hook script does not exist: {}", &req.path);
            continue;
        }
        let ipv4_addr = if let Some(ipv4_addr) = &req.ipv4_addr {
            ipv4_addr.to_string()
        } else {
            String::new()
        };
        let ipv6_addr = if let Some(ipv6_addr) = &req.ipv6_addr {
            ipv6_addr.to_string()
        } else {
            String::new()
        };
        if let Err(e) = std::process::Command::new(&req.path)
            .env("IPOED_HOOK_EVENT", req.event.as_str())
            .env("IPOED_WAN_IF", &req.wan_if)
            .env("IPOED_LAN_IF", &req.lan_if)
            .env("IPOED_IPV4_ADDR", &ipv4_addr)
            .env("IPOED_IPV6_ADDR", &ipv6_addr)
            .status()
        {
            println!("Hook exec error: {e}");
        }
    }
    println!("Hook thread exited");
}

pub fn init(ch_tx: mpsc::Sender<IpoedMsg>) -> Result<mpsc::Sender<HookReq>, String> {
    let (req_tx, req_rx) = mpsc::channel::<HookReq>();

    std::thread::spawn(move || {
        hook(ch_tx, req_rx);
    });

    Ok(req_tx)
}
