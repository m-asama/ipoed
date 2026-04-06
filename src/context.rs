// SPDX-License-Identifier: MIT
// Copyright(c) 2026 Masakazu Asama

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::sync::mpsc;
use std::time::Duration;
use std::time::Instant;

use crate::dhcp6;
use crate::hb46pp;
use crate::hook;
use crate::icmp6;
use crate::rtnl;
use crate::timer;
use crate::utils;

use crate::{Config, IpoedMsg};

pub const IPOETUN_NAME: &str = "ipoetun";
pub const PERIODIC_INTERVAL: u64 = 1000;

#[derive(Debug, PartialEq)]
enum IpoedState {
    Init,
    Icmp6RaWaiting,
    Dhcp6AdvertWaiting,
    Dhcp6ReplyWaiting,
    Ready,
    Dhcp6Renewing,
}

#[derive(Debug, PartialEq)]
enum IpoedMode {
    Init,
    Ra,
    Pd,
}

#[derive(Debug)]
pub struct Context {
    wan_if_name: String,
    pub wan_if_index: i32,
    wan_if_hw_addr: [u8; 6],
    wan_if_ll_addr: Ipv6Addr,
    lan_if_name: String,
    pub lan_if_index: i32,
    lan_if_hw_addr: [u8; 6],
    lan_if_ll_addr: Ipv6Addr,
    lan_iid: Ipv6Addr,
    dns_server_self: bool,
    lan_addr4: Option<(Ipv4Addr, u8)>,
    disable_hb46pp: bool,
    hook_path: String,
    debug: bool,
    //
    pub ch_tx: mpsc::Sender<IpoedMsg>,
    pub ch_rx: mpsc::Receiver<IpoedMsg>,
    timer_tx: mpsc::Sender<timer::TimerReq>,
    hook_tx: mpsc::Sender<hook::HookReq>,
    hb46pp_tx: mpsc::Sender<hb46pp::Hb46ppReq>,
    pub sk_icmp6: libc::c_int,
    pub sk_dhcp6s: libc::c_int,
    pub sk_dhcp6c: libc::c_int,
    //
    mode: IpoedMode,
    state: IpoedState,
    gateway_run: Option<Ipv6Addr>,
    gateway_can: Option<Ipv6Addr>,
    prefix_run: Option<Ipv6Addr>,
    prefix_can: Option<Ipv6Addr>,
    dns_servers: Vec<Ipv6Addr>,
    dns_searchs: Vec<String>,
    //
    hb46pp_user: Option<String>,
    hb46pp_pass: Option<String>,
    hb46pp_run: Option<hb46pp::Hb46ppConfig>,
    hb46pp_can: Option<hb46pp::Hb46ppConfig>,
    hb46pp_next: Instant,
    //
    icmp6s_nas: HashMap<Ipv6Addr, (icmp6::NeighAdvertMsg, Instant)>,
    icmp6s_next_ts: Instant,
    //
    icmp6c_ras: HashMap<Ipv6Addr, (icmp6::RtAdvertMsg, Instant)>,
    icmp6c_rs_sent_count: usize,
    //
    dhcp6c_advs: HashMap<Ipv6Addr, (dhcp6::AdvertiseMsg, Instant)>,
    dhcp6c_reps: HashMap<Ipv6Addr, (dhcp6::ReplyMsg, Instant)>,
    dhcp6c_last_tid: u32,
    dhcp6c_last_ts: Instant,
    dhcp6c_last_rt: u64,
    dhcp6c_req_sent_count: usize,
}

impl Context {
    pub fn from_conf(conf: Config) -> Result<Self, String> {
        let wan_if_name = match conf.wan_if {
            Some(wan_if_name) => wan_if_name,
            None => return Err(format!("WAN interface required")),
        };
        let lan_if_name = match conf.lan_if {
            Some(lan_if_name) => lan_if_name,
            None => return Err(format!("LAN interface required")),
        };
        if wan_if_name == lan_if_name {
            return Err(format!(
                "Cannot assign the same interface to both WAN and LAN"
            ));
        }
        if let Some(lan_iid) = &conf.lan_iid
            && lan_iid.octets()[0..8] != [0u8; 8]
        {
            return Err(format!("Invalid LAN IID"));
        }
        let lan_addr4 = conf.lan_addr4;
        let mut wan_if_index: Option<i32> = None;
        let mut wan_if_hw_addr: Option<[u8; 6]> = None;
        let mut wan_if_ll_addr: Option<Ipv6Addr> = None;
        let mut lan_if_index: Option<i32> = None;
        let mut lan_if_hw_addr: Option<[u8; 6]> = None;
        let mut lan_if_ll_addr: Option<Ipv6Addr> = None;
        let links = match rtnl::dump_links() {
            Ok(links) => links,
            Err(e) => return Err(format!("Dump links failed: {e}")),
        };
        for link in links {
            if let Some(ifname) = link.ifname {
                if ifname == wan_if_name {
                    wan_if_index = Some(link.index);
                    wan_if_hw_addr = link.address;
                }
                if ifname == lan_if_name {
                    lan_if_index = Some(link.index);
                    lan_if_hw_addr = link.address;
                }
            }
        }
        let wan_if_index = match wan_if_index {
            Some(wan_if_index) => wan_if_index,
            None => return Err(format!("WAN interface not found")),
        };
        let wan_if_hw_addr = match wan_if_hw_addr {
            Some(wan_if_hw_addr) => wan_if_hw_addr,
            None => return Err(format!("WAN interface H/W address unknown")),
        };
        let lan_if_index = match lan_if_index {
            Some(lan_if_index) => lan_if_index,
            None => return Err(format!("LAN interface not found")),
        };
        let lan_if_hw_addr = match lan_if_hw_addr {
            Some(lan_if_hw_addr) => lan_if_hw_addr,
            None => return Err(format!("LAN interface H/W address unknown")),
        };
        let addrs = match rtnl::dump_ipv6_addrs() {
            Ok(addrs) => addrs,
            Err(e) => return Err(format!("Dump IPv6 addresses failed: {e}")),
        };
        for addr in addrs {
            if addr.index == wan_if_index && addr.scope == rtnl::Scope::Link {
                wan_if_ll_addr = addr.address6;
            }
            if addr.index == lan_if_index && addr.scope == rtnl::Scope::Link {
                lan_if_ll_addr = addr.address6;
            }
        }
        let wan_if_ll_addr = match wan_if_ll_addr {
            Some(wan_if_ll_addr) => wan_if_ll_addr,
            None => return Err(format!("WAN IPv6 link-local address unknown")),
        };
        let lan_if_ll_addr = match lan_if_ll_addr {
            Some(lan_if_ll_addr) => lan_if_ll_addr,
            None => return Err(format!("LAN IPv6 link-local address unknown")),
        };
        let lan_iid = if let Some(lan_iid) = conf.lan_iid {
            lan_iid
        } else {
            let segs = lan_if_ll_addr.segments();
            Ipv6Addr::from_segments([0, 0, 0, 0, segs[4], segs[5], segs[6], segs[7]])
        };
        let (ch_tx, ch_rx): (mpsc::Sender<IpoedMsg>, mpsc::Receiver<IpoedMsg>) = mpsc::channel();
        let timer_tx = match timer::init(ch_tx.clone()) {
            Ok(timer_tx) => timer_tx,
            Err(e) => return Err(format!("Timer init error: {e}")),
        };
        let hook_tx = match hook::init(ch_tx.clone()) {
            Ok(hook_tx) => hook_tx,
            Err(e) => return Err(format!("Hook init error: {e}")),
        };
        let hb46pp_tx = match hb46pp::init(ch_tx.clone()) {
            Ok(hb46pp_tx) => hb46pp_tx,
            Err(e) => return Err(format!("HB46PP init error: {e}")),
        };
        let icmp6s_nas = HashMap::<Ipv6Addr, (icmp6::NeighAdvertMsg, Instant)>::new();
        let icmp6c_ras = HashMap::<Ipv6Addr, (icmp6::RtAdvertMsg, Instant)>::new();
        let dhcp6c_advs = HashMap::<Ipv6Addr, (dhcp6::AdvertiseMsg, Instant)>::new();
        let dhcp6c_reps = HashMap::<Ipv6Addr, (dhcp6::ReplyMsg, Instant)>::new();
        Ok(Self {
            wan_if_name: wan_if_name,
            wan_if_index: wan_if_index,
            wan_if_hw_addr: wan_if_hw_addr,
            wan_if_ll_addr: wan_if_ll_addr,
            lan_if_name: lan_if_name,
            lan_if_index: lan_if_index,
            lan_if_hw_addr: lan_if_hw_addr,
            lan_if_ll_addr: lan_if_ll_addr,
            lan_iid: lan_iid,
            dns_server_self: conf.dns_server_self,
            lan_addr4: lan_addr4,
            disable_hb46pp: conf.disable_hb46pp,
            hook_path: conf.hook_path,
            debug: conf.debug,
            //
            ch_tx: ch_tx,
            ch_rx: ch_rx,
            timer_tx: timer_tx,
            hook_tx: hook_tx,
            hb46pp_tx: hb46pp_tx,
            sk_icmp6: -1,
            sk_dhcp6s: -1,
            sk_dhcp6c: -1,
            //
            mode: IpoedMode::Init,
            state: IpoedState::Init,
            gateway_run: None,
            gateway_can: None,
            prefix_run: None,
            prefix_can: None,
            dns_servers: Vec::<Ipv6Addr>::new(),
            dns_searchs: Vec::<String>::new(),
            //
            hb46pp_user: conf.hb46pp_user,
            hb46pp_pass: conf.hb46pp_pass,
            hb46pp_run: None,
            hb46pp_can: None,
            hb46pp_next: Instant::now(),
            //
            icmp6s_nas: icmp6s_nas,
            icmp6s_next_ts: Instant::now(),
            //
            icmp6c_ras: icmp6c_ras,
            icmp6c_rs_sent_count: 0,
            //
            dhcp6c_advs: dhcp6c_advs,
            dhcp6c_reps: dhcp6c_reps,
            dhcp6c_last_tid: 0,
            dhcp6c_last_ts: Instant::now() - Duration::from_secs(86400),
            dhcp6c_last_rt: 0,
            dhcp6c_req_sent_count: 0,
        })
    }

    fn is_wan_if(&self, ifi: &Option<i32>) -> bool {
        if let Some(ifi) = ifi
            && *ifi == self.wan_if_index
        {
            true
        } else {
            false
        }
    }

    fn is_lan_if(&self, ifi: &Option<i32>) -> bool {
        if let Some(ifi) = ifi
            && *ifi == self.lan_if_index
        {
            true
        } else {
            false
        }
    }

    fn ipv6_ready(&self) -> bool {
        self.state == IpoedState::Ready || self.state == IpoedState::Dhcp6Renewing
    }

    pub fn setup(&self) -> Result<(), String> {
        if !utils::ipv6_forwarding(&self.wan_if_name) {
            return Err(format!("WAN interface is not forwarding"));
        }
        if !utils::ipv6_forwarding(&self.lan_if_name) {
            return Err(format!("LAN interface is not forwarding"));
        }
        if !std::path::Path::new("/etc/systemd/resolved.conf.d").is_dir() {
            return Err(format!(
                "Directory /etc/systemd/resolved.conf.d does not exist"
            ));
        }
        if let Some((lan_addr4, lan_plen4)) = &self.lan_addr4 {
            if let Err(e) = rtnl::rep_ipv4_addr(lan_addr4, *lan_plen4, self.lan_if_index) {
                return Err(format!("LAN IPv4 address set failed: {e}"));
            }
        }
        Ok(())
    }

    fn reset(&mut self) -> Result<(), String> {
        if self.debug {
            println!("Reset called");
        }
        if self.mode == IpoedMode::Ra {
            if let Err(e) = rtnl::set_promisc(self.wan_if_index, false) {
                println!("Set WAN interface promisc off failed: {e}");
            }
        }
        self.mode = IpoedMode::Init;
        self.state = IpoedState::Init;
        self.gateway_can = None;
        self.prefix_can = None;
        self.dns_servers = Vec::<Ipv6Addr>::new();
        self.dns_searchs = Vec::<String>::new();
        self.icmp6c_ras = HashMap::<Ipv6Addr, (icmp6::RtAdvertMsg, Instant)>::new();
        self.dhcp6c_advs = HashMap::<Ipv6Addr, (dhcp6::AdvertiseMsg, Instant)>::new();
        self.dhcp6c_reps = HashMap::<Ipv6Addr, (dhcp6::ReplyMsg, Instant)>::new();
        self.hb46pp_can = None;
        self.hb46pp_next = Instant::now();
        self.dhcp6c_req_sent_count = 0;
        self.timer_req(
            timer::TimerMsg::RsSolicitSendDelayTimeout,
            rand::random_range(0..icmp6::MAX_RTR_SOLICITATION_DELAY),
        );
        Ok(())
    }

    fn commit_hb46pp(&mut self) -> Result<(), String> {
        if let Some(hb46pp) = &self.hb46pp_run
            && self.hb46pp_can.is_none()
        {
            if self.debug {
                println!("Commit HB46PP called");
            }
            // 設定した hb46pptun を消す。
            let wan_addr = if let Some((wan_addr, _)) = &hb46pp.ipv4 {
                Some(wan_addr.clone())
            } else {
                None
            };
            match rtnl::get_link_by_name(IPOETUN_NAME) {
                Ok(ipoetun) => {
                    println!("Deleting link {}:{}", ipoetun.index, ipoetun.ifname_s());
                    if let Err(e) = rtnl::del_ip6tnl_link(ipoetun.index) {
                        println!(
                            "Failed to delete link {}:{}: {}",
                            ipoetun.index,
                            ipoetun.ifname_s(),
                            e
                        );
                    }
                }
                Err(e) => {
                    println!("Link {IPOETUN_NAME} not found: {e}");
                }
            }
            self.hb46pp_run = None;
            self.hook_req(hook::HookEvent::Ipv4Down, wan_addr, None);
        }
        if let Some(hb46pp) = &self.hb46pp_can
            && self.hb46pp_run != self.hb46pp_can
        {
            // 新しい hb46pptun を設定する。
            let wan_addr = if let Some((wan_addr, _)) = &hb46pp.ipv4 {
                Some(wan_addr.clone())
            } else {
                None
            };
            let remote = &hb46pp.ipv6_remote;
            let local = if let Some(local) = &hb46pp.ipv6_local {
                Some(local)
            } else {
                if let Some(lan_prefix) = &self.prefix_run {
                    Some(&utils::ipv6_address(lan_prefix, &self.lan_iid))
                } else {
                    None
                }
            };
            if let Some(local) = local {
                let ifindex = match rtnl::get_link_by_name(IPOETUN_NAME) {
                    Ok(ipoetun) => Some(ipoetun.index),
                    Err(_) => None,
                };
                if let Some(ifindex) = ifindex {
                    println!(
                        "Setting link {}:{} local {} remote {}",
                        ifindex, IPOETUN_NAME, local, remote
                    );
                    if let Err(e) =
                        rtnl::set_ip6tnl_link(ifindex, IPOETUN_NAME, Some(true), local, remote)
                    {
                        println!("Set {IPOETUN_NAME} failed: {e}");
                    }
                } else {
                    println!(
                        "Creating link {} local {} remote {}",
                        IPOETUN_NAME, local, remote
                    );
                    if let Err(e) = rtnl::new_ip6tnl_link(IPOETUN_NAME, true, local, remote) {
                        println!("Create {IPOETUN_NAME} failed: {e}");
                    }
                }
            } else {
                println!("Get {IPOETUN_NAME} local address failed");
            }
            match rtnl::get_link_by_name(IPOETUN_NAME) {
                Ok(ipoetun) => {
                    if let Some(local) = local {
                        // ローカル側トンネル終端 IPv6 アドレスを設定する。
                        println!(
                            "Setting IPv6 address {}/{} to {}:{}",
                            local,
                            128,
                            ipoetun.index,
                            ipoetun.ifname_s()
                        );
                        if let Err(e) = rtnl::rep_ipv6_addr(local, 128, ipoetun.index) {
                            println!("Set IPv6 address failed: {e}");
                        }
                    }
                    if let Some((addr4, plen4)) = &hb46pp.ipv4 {
                        // トンネル IPv4 アドレスを設定する。
                        println!(
                            "Setting IPv4 address {}/{} to {}:{}",
                            addr4,
                            plen4,
                            ipoetun.index,
                            ipoetun.ifname_s()
                        );
                        if let Err(e) = rtnl::rep_ipv4_addr(addr4, *plen4, ipoetun.index) {
                            println!("Set IPv4 address failed: {e}");
                        }
                    }
                    //
                    println!(
                        "Setting IPv4 default route to link {}:{}",
                        ipoetun.index,
                        ipoetun.ifname_s()
                    );
                    if let Err(e) = rtnl::rep_ipv4_route(
                        &Ipv4Addr::from_str("0.0.0.0").unwrap(),
                        0,
                        None,
                        ipoetun.index,
                    ) {
                        println!("Set IPv4 default route failed: {e}");
                    }
                }
                Err(e) => println!("Link {IPOETUN_NAME} not found: {e}"),
            };
            self.hb46pp_run = self.hb46pp_can.clone();
            self.hook_req(hook::HookEvent::Ipv4Up, wan_addr, None);
        }
        Ok(())
    }

    fn commit(&mut self) -> Result<(), String> {
        if let Some(gateway) = &self.gateway_run
            && self.gateway_can.is_none()
        {
            if self.debug {
                println!("Commit called");
            }
            // 設定した default gateway を消す。
            println!(
                "Deleting IPv6 default route via {} dev {}:{}",
                gateway, self.wan_if_index, self.wan_if_name
            );
            if let Err(e) = rtnl::del_ipv6_route(
                &Ipv6Addr::from_str("::").unwrap(),
                0,
                Some(gateway),
                self.wan_if_index,
            ) {
                println!("Failed to delete IPv6 default route: {e}");
            }
            self.gateway_run = None;
        }
        if let Some(prefix) = &self.prefix_run
            && self.prefix_can.is_none()
        {
            // 設定した LAN I/F の IPv6 アドレスを消す。
            let lan_addr = utils::ipv6_address(prefix, &self.lan_iid);
            println!(
                "Deleting IPv6 address {}/{} to {}:{}",
                lan_addr, 64, self.lan_if_index, self.lan_if_name
            );
            if let Err(e) = rtnl::del_ipv6_addr(&lan_addr, 64, self.lan_if_index) {
                println!("Failed to delete IPv6 address: {e}");
            }
            self.prefix_run = None;
            self.hook_req(hook::HookEvent::Ipv6Down, None, Some(lan_addr.clone()));
        }
        if let Some(gateway) = &self.gateway_can
            && self.gateway_run != self.gateway_can
        {
            // 新しい default gateway を設定する。
            println!(
                "Setting IPv6 default route via {} dev {}:{}",
                gateway, self.wan_if_index, self.wan_if_name
            );
            if let Err(e) = rtnl::rep_ipv6_route(
                &Ipv6Addr::from_str("::").unwrap(),
                0,
                Some(gateway),
                self.wan_if_index,
            ) {
                println!("Set IPv6 default route error: {e}");
            }
            self.gateway_run = self.gateway_can.clone();
        }
        if let Some(prefix) = &self.prefix_can
            && self.prefix_run != self.prefix_can
        {
            // 新しい LAN I/F の IPv6 アドレスを設定する。
            let lan_addr = utils::ipv6_address(prefix, &self.lan_iid);
            println!(
                "Setting IPv6 address {}/{} to {}:{}",
                lan_addr, 64, self.lan_if_index, self.lan_if_name
            );
            if let Err(e) = rtnl::rep_ipv6_addr(&lan_addr, 64, self.lan_if_index) {
                println!("Set IPv6 address error: {e}");
            }
            self.prefix_run = self.prefix_can.clone();
            self.hook_req(hook::HookEvent::Ipv6Up, None, Some(lan_addr.clone()));
        }
        utils::resolved_conf_update(&self.dns_servers, &self.dns_searchs);
        self.commit_hb46pp()
    }

    pub fn timer_req(&self, msg: timer::TimerMsg, ms: u64) {
        if let Err(e) = self.timer_tx.send(timer::TimerReq {
            msg: msg,
            after: Duration::from_millis(ms),
        }) {
            println!("Failed to send timer request: {e}");
        }
    }

    fn hook_req(
        &self,
        event: hook::HookEvent,
        ipv4_addr: Option<Ipv4Addr>,
        ipv6_addr: Option<Ipv6Addr>,
    ) {
        if self.debug {
            println!("Sending hook request");
        }
        if let Err(e) = self.hook_tx.send(hook::HookReq {
            path: self.hook_path.clone(),
            event: event,
            wan_if: self.wan_if_name.to_string(),
            lan_if: self.lan_if_name.to_string(),
            ipv4_addr: ipv4_addr,
            ipv6_addr: ipv6_addr,
        }) {
            println!("Failed to send hook request: {e}");
        }
    }

    fn send_rs(&mut self) {
        if self.debug {
            println!(
                "Sending ICMPv6 RS via {}:{}",
                self.wan_if_index, self.wan_if_name
            );
        }
        if let Err(e) = icmp6::send_rs(
            self.sk_icmp6,
            self.wan_if_index,
            self.wan_if_hw_addr,
            &self.wan_if_ll_addr,
        ) {
            println!("Failed to send ICMPv6 RS: {e}");
            return;
        }
        self.icmp6c_rs_sent_count += 1;
    }

    fn send_ra(&mut self, dst_addr: Option<&Ipv6Addr>, withdraw: bool) -> u16 {
        if !self.ipv6_ready() {
            return 0;
        }
        if self.debug {
            println!(
                "Sending ICMPv6 RA via {}:{}",
                self.lan_if_index, self.lan_if_name
            );
        }
        let gateway = if let Some(gateway) = &self.gateway_run {
            gateway
        } else {
            println!("Ready state but gateway is missing");
            return 0;
        };
        let prefix = if let Some(prefix) = &self.prefix_run {
            prefix
        } else {
            println!("Ready state but prefix is missing");
            return 0;
        };
        let ra = if let Some((ra, _)) = &self.icmp6c_ras.get(gateway) {
            ra
        } else {
            println!("Ready state but no ICMPv6 RA is cached");
            return 0;
        };
        let router_lifetime = if withdraw { 0 } else { ra.router_lifetime };
        let reachable_time = ra.reachable_time;
        let retrans_timer = ra.retrans_timer;
        let prefix_len = 64;
        let valid_lifetime;
        let preferred_lifetime;
        match self.mode {
            IpoedMode::Ra => {
                let mut lifetimes: Option<(u32, u32)> = None;
                for prefix_info in &ra.prefix_infos {
                    if prefix_info.prefix == *prefix {
                        lifetimes =
                            Some((prefix_info.valid_lifetime, prefix_info.preferred_lifetime));
                    }
                }
                if let Some(lifetimes) = lifetimes {
                    valid_lifetime = lifetimes.0;
                    preferred_lifetime = lifetimes.1;
                } else {
                    println!("Matching prefix not found in cached ICMPv6 RA");
                    return 0;
                }
            }
            IpoedMode::Pd => {
                let rep = if let Some((rep, _)) = &self.dhcp6c_reps.get(gateway) {
                    rep
                } else {
                    println!("Ready state but no DHCPv6 Reply is cached");
                    return 0;
                };
                let mut lifetimes: Option<(u32, u32)> = None;
                for ia_pd in &rep.ia_pds {
                    for ia_prefix in &ia_pd.ia_prefixes {
                        if ia_prefix.ipv6_prefix == *prefix {
                            lifetimes =
                                Some((ia_prefix.valid_lifetime, ia_prefix.preferred_lifetime));
                        }
                    }
                }
                if let Some(lifetimes) = lifetimes {
                    valid_lifetime = lifetimes.0;
                    preferred_lifetime = lifetimes.1;
                } else {
                    println!("DHCPv6 Reply does not contain a matching IA_PD prefix");
                    return 0;
                }
            }
            IpoedMode::Init => {
                return 0;
            }
        }
        if let Err(e) = icmp6::send_ra(
            self.sk_icmp6,
            self.lan_if_index,
            self.lan_if_hw_addr,
            &self.lan_if_ll_addr,
            dst_addr,
            router_lifetime,
            reachable_time,
            retrans_timer,
            prefix,
            prefix_len,
            valid_lifetime,
            preferred_lifetime,
        ) {
            println!("Failed to send ICMPv6 RA: {e}");
        }
        router_lifetime
    }

    fn send_ns(&mut self, tgt_addr: &Ipv6Addr) {
        if self.debug {
            println!(
                "Sending ICMPv6 NS via {}:{}",
                self.lan_if_index, self.lan_if_name
            );
        }
        if let Err(e) = icmp6::send_ns(
            self.sk_icmp6,
            self.lan_if_index,
            self.lan_if_hw_addr,
            &self.lan_if_ll_addr,
            tgt_addr,
        ) {
            println!("Failed to send ICMPv6 NS: {e}");
        }
    }

    fn send_na(&mut self, dst_addr: Option<&Ipv6Addr>, tgt_hwaddr: [u8; 6], tgt_addr: &Ipv6Addr) {
        if self.debug {
            println!(
                "Sending ICMPv6 NA via {}:{}",
                self.wan_if_index, self.wan_if_name
            );
        }
        if let Err(e) = icmp6::send_na(
            self.sk_icmp6,
            self.wan_if_index,
            &self.wan_if_ll_addr,
            dst_addr,
            tgt_hwaddr,
            tgt_addr,
        ) {
            println!("Failed to send ICMPv6 NA: {e}");
        }
    }

    fn send_sol(&mut self, ia_pd: bool, re: bool) {
        if self.debug {
            println!(
                "Sending DHCPv6 Solicit via {}:{}",
                self.wan_if_index, self.wan_if_name
            );
        }
        let (transaction_id, elapsed_time) = if re {
            (self.dhcp6c_last_tid, self.dhcp6c_elapsed_time())
        } else {
            self.dhcp6c_transaction_renew();
            (self.dhcp6c_last_tid, 0)
        };
        if let Err(e) = dhcp6::send_sol(
            self.sk_dhcp6c,
            self.wan_if_index,
            self.wan_if_hw_addr,
            &self.wan_if_ll_addr,
            transaction_id,
            elapsed_time,
            ia_pd,
        ) {
            println!("Failed to send DHCPv6 Solicit: {e}");
        }
    }

    fn send_req(&mut self, re: bool) {
        if self.debug {
            println!(
                "Sending DHCPv6 Request via {}:{}",
                self.wan_if_index, self.wan_if_name
            );
        }
        let gateway = if let Some(gateway) = &self.gateway_can {
            gateway
        } else {
            println!("XXX: BUG? no gateway: state={:?}", self.state);
            return;
        };
        if self.dhcp6c_advs.len() == 0 {
            println!("XXX: BUG? no DHCPv6 Advertise: state={:?}", self.state);
            return;
        }
        let adv = if let Some((adv, _)) = self.dhcp6c_advs.get(gateway) {
            adv
        } else {
            // self.dhcp6c_advs.len() > 0 であることを前提。
            println!("ICMPv6 RA and DHCPv6 Advertise source does not match");
            let mut adv: Option<&dhcp6::AdvertiseMsg> = None;
            for (_, (tmp, _)) in &self.dhcp6c_advs {
                if adv.is_none() {
                    adv = Some(tmp);
                } else if let Some(tmp_pref) = &tmp.pref {
                    if let Some(adv_pref) = &adv.unwrap().pref {
                        if tmp_pref.pref_value > adv_pref.pref_value {
                            adv = Some(tmp);
                        }
                    } else {
                        adv = Some(tmp);
                    }
                }
            }
            adv.unwrap()
        };
        if adv.ia_pds.len() == 0 {
            println!("DHCPv6 Advertise has no IA_PD");
            return;
        }
        if adv.ia_pds[0].ia_prefixes.len() == 0 {
            println!("DHCPv6 Advertise IA_PD has no IA prefixes");
            return;
        }
        let server_id = &adv.server_id.clone();
        let ia_prefixes = &adv.ia_pds[0].ia_prefixes.clone();
        let (transaction_id, elapsed_time) = if re {
            (self.dhcp6c_last_tid, self.dhcp6c_elapsed_time())
        } else {
            self.dhcp6c_transaction_renew();
            (self.dhcp6c_last_tid, 0)
        };
        if let Err(e) = dhcp6::send_req(
            self.sk_dhcp6c,
            self.wan_if_index,
            self.wan_if_hw_addr,
            &self.wan_if_ll_addr,
            transaction_id,
            elapsed_time,
            server_id,
            ia_prefixes,
        ) {
            println!("Failed to send DHCPv6 Request: {e}");
        }
        self.dhcp6c_req_sent_count += 1;
    }

    fn send_ren(&mut self, re: bool) {
        if self.debug {
            println!(
                "Sending DHCPv6 Renew via {}:{}",
                self.wan_if_index, self.wan_if_name
            );
        }
        let gateway = if let Some(gateway) = &self.gateway_run {
            gateway
        } else {
            println!("XXX: BUG? no gateway: state={:?}", self.state);
            return;
        };
        let prefix = if let Some(prefix) = &self.prefix_run {
            prefix
        } else {
            println!("XXX: BUG? no prefix: state={:?}", self.state);
            return;
        };
        let rep = if let Some((rep, _)) = self.dhcp6c_reps.get(gateway) {
            rep
        } else {
            println!(
                "XXX: BUG? no DHCPv6 Reply for {}: state={:?}",
                gateway, self.state
            );
            return;
        };
        let server_id = rep.server_id.clone();
        let mut ia_prefixes: Option<Vec<dhcp6::IaPrefixOpt>> = None;
        for ia_pd in &rep.ia_pds {
            for ia_prefix in &ia_pd.ia_prefixes {
                if ia_prefix.ipv6_prefix == *prefix {
                    ia_prefixes = Some(ia_pd.ia_prefixes.clone());
                }
            }
        }
        let ia_prefixes = if let Some(ia_prefixes) = ia_prefixes {
            ia_prefixes
        } else {
            println!(
                "XXX: BUG? DHCPv6 Reply IA_PD has no IA prefixes: state={:?}",
                self.state
            );
            return;
        };
        let (transaction_id, elapsed_time) = if re {
            (self.dhcp6c_last_tid, self.dhcp6c_elapsed_time())
        } else {
            self.dhcp6c_transaction_renew();
            (self.dhcp6c_last_tid, 0)
        };
        if let Err(e) = dhcp6::send_ren(
            self.sk_dhcp6c,
            self.wan_if_index,
            self.wan_if_hw_addr,
            &self.wan_if_ll_addr,
            transaction_id,
            elapsed_time,
            &server_id,
            &ia_prefixes,
        ) {
            println!("Failed to send DHCPv6 Renew: {e}");
        }
    }

    fn send_rep(
        &mut self,
        transaction_id: u32,
        dst_addr: &Ipv6Addr,
        client_id: &Option<dhcp6::ClientIdOpt>,
    ) {
        if self.debug {
            println!(
                "Sending DHCPv6 Reply via {}:{}",
                self.lan_if_index, self.lan_if_name
            );
        }
        let dns_servers = if let Some(prefix) = &self.prefix_run
            && self.dns_server_self
        {
            &vec![utils::ipv6_address(prefix, &self.lan_iid)]
        } else {
            &self.dns_servers
        };
        if let Err(e) = dhcp6::send_rep(
            self.sk_dhcp6s,
            self.lan_if_index,
            self.lan_if_hw_addr,
            &self.lan_if_ll_addr,
            transaction_id,
            dst_addr,
            client_id,
            dns_servers,
            &self.dns_searchs,
        ) {
            println!("Failed to send DHCPv6 Reply: {e}");
        }
    }

    fn send_inf(&mut self, re: bool) {
        if self.debug {
            println!(
                "Sending DHCPv6 Information-request via {}:{}",
                self.wan_if_index, self.wan_if_name
            );
        }
        let (transaction_id, elapsed_time) = if re {
            (self.dhcp6c_last_tid, self.dhcp6c_elapsed_time())
        } else {
            self.dhcp6c_transaction_renew();
            (self.dhcp6c_last_tid, 0)
        };
        if let Err(e) = dhcp6::send_inf(
            self.sk_dhcp6c,
            self.wan_if_index,
            self.wan_if_hw_addr,
            &self.wan_if_ll_addr,
            transaction_id,
            elapsed_time,
        ) {
            println!("Failed to send DHCPv6 Information-request: {e}");
        }
    }

    fn dhcp6c_transaction_renew(&mut self) {
        self.dhcp6c_last_tid = rand::random_range(0x0..0x01000000);
        self.dhcp6c_last_ts = Instant::now();
        self.dhcp6c_last_rt = 0;
    }

    fn dhcp6c_elapsed_time(&self) -> u16 {
        let elapsed_time = (Instant::now() - self.dhcp6c_last_ts).as_millis();
        let elapsed_time = (elapsed_time / 10) as u16;
        elapsed_time
    }

    fn dhcp6c_rand(&self) -> f64 {
        rand::random_range(-0.1..=0.1)
    }

    fn dhcp6c_rt_init(&self, irt: u64) -> u64 {
        let rand = self.dhcp6c_rand();
        let rt = irt + (rand * irt as f64) as u64;
        rt
    }

    fn dhcp6c_rt(&self, mrt: u64) -> u64 {
        let rand = self.dhcp6c_rand();
        let rt = 2 * self.dhcp6c_last_rt + (rand * self.dhcp6c_last_rt as f64) as u64;
        if rt > mrt { mrt } else { rt }
    }

    pub fn recv_timer_msg(&mut self, msg: timer::TimerMsg) {
        match msg {
            timer::TimerMsg::RsSolicitSendDelayTimeout => match self.state {
                IpoedState::Init => {
                    // 起動直後。WAN I/F から RS を送信し RTR_SOLICITATION_INTERVAL 待つ。
                    self.send_rs();
                    self.timer_req(
                        timer::TimerMsg::RsSolicitWaitTimeout,
                        icmp6::RTR_SOLICITATION_INTERVAL,
                    );
                    // Icmp6RaWaiting へ移行。
                    self.state = IpoedState::Icmp6RaWaiting;
                }
                _ => {
                    if self.debug {
                        println!("recv_timer_msg: msg={:?} state={:?}", msg, self.state);
                    }
                }
            },
            timer::TimerMsg::RsSolicitWaitTimeout => match self.state {
                IpoedState::Icmp6RaWaiting => {
                    // RA を待っている状態。
                    // すでに MAX_RTR_SOLICITATIONS 回 RS を送っていたら何もしない。
                    if self.icmp6c_rs_sent_count >= icmp6::MAX_RTR_SOLICITATIONS {
                        return;
                    }
                    // WAN I/F から RS を送信し RTR_SOLICITATION_INTERVAL 待つ。
                    self.send_rs();
                    self.timer_req(
                        timer::TimerMsg::RsSolicitWaitTimeout,
                        icmp6::RTR_SOLICITATION_INTERVAL,
                    );
                }
                _ => {
                    if self.debug {
                        println!("recv_timer_msg: msg={:?} state={:?}", msg, self.state);
                    }
                }
            },
            timer::TimerMsg::Dhcp6AdvertWaitTimeout => match self.state {
                IpoedState::Dhcp6AdvertWaiting => {
                    if self.dhcp6c_advs.len() > 0 {
                        // DHCPv6 Advertise message をいくつか受信している。
                        self.send_req(false);
                        let rt = self.dhcp6c_rt_init(dhcp6::REQ_TIMEOUT);
                        self.timer_req(timer::TimerMsg::Dhcp6ReplyWaitTimeout, rt);
                        self.dhcp6c_last_rt = rt;
                        self.state = IpoedState::Dhcp6ReplyWaiting;
                    } else {
                        // まだ DHCPv6 Advertise message をひとつも受信していない。
                        let ia_pd = if self.mode == IpoedMode::Pd {
                            true
                        } else {
                            false
                        };
                        self.send_sol(ia_pd, true);
                        let rt = self.dhcp6c_rt(dhcp6::SOL_MAX_RT);
                        self.timer_req(timer::TimerMsg::Dhcp6AdvertWaitTimeout, rt);
                        self.dhcp6c_last_rt = rt;
                    }
                }
                _ => {
                    if self.debug {
                        println!("recv_timer_msg: msg={:?} state={:?}", msg, self.state);
                    }
                }
            },
            timer::TimerMsg::Dhcp6ReplyWaitTimeout => match self.state {
                IpoedState::Dhcp6ReplyWaiting => {
                    if self.dhcp6c_reps.len() > 0 {
                        // DHCPv6 Reply message をいくつか受信している。
                        let gateway = if let Some(gateway) = &self.gateway_can {
                            gateway
                        } else {
                            println!("XXX: BUG? no gateway: state={:?}", self.state);
                            return;
                        };
                        let rep = if let Some((rep, _)) = self.dhcp6c_reps.get(gateway) {
                            rep
                        } else {
                            // self.dhcp6c_reps.len() > 0 であることを前提。
                            println!("ICMPv6 RA and DHCPv6 Reply source does not match");
                            let mut rep: Option<&dhcp6::ReplyMsg> = None;
                            for (_, (tmp, _)) in &self.dhcp6c_reps {
                                rep = Some(tmp);
                                break;
                            }
                            rep.unwrap()
                        };
                        if self.mode == IpoedMode::Pd {
                            if rep.ia_pds.len() == 0 {
                                println!("DHCPv6 Reply has no IA_PD");
                                return;
                            }
                            if rep.ia_pds[0].ia_prefixes.len() == 0 {
                                println!("DHCPv6 Reply IA_PD has no IA prefixes");
                                return;
                            }
                            self.prefix_can =
                                Some(rep.ia_pds[0].ia_prefixes[0].ipv6_prefix.clone());
                        }
                        if let Some(dns_recursive_name_server) = &rep.dns_recursive_name_server {
                            self.dns_servers =
                                dns_recursive_name_server.dns_recursive_name_servers.clone();
                        }
                        if let Some(domain_search_list) = &rep.domain_search_list {
                            self.dns_searchs = domain_search_list.searchs.clone();
                        }
                        if let Err(e) = self.commit() {
                            println!("Commit failed: {e}");
                            return;
                        }
                        self.state = IpoedState::Ready;
                        // IPv6 反映直後は HB46PP がうまくいかない場合があるので 5 秒遅延させる。
                        self.hb46pp_next = Instant::now() + Duration::from_secs(5);
                    } else {
                        // まだ DHCPv6 Reply message をひとつも受信していない。
                        match self.mode {
                            IpoedMode::Ra => {
                                self.send_inf(true);
                                let rt = self.dhcp6c_rt(dhcp6::INF_MAX_RT);
                                self.timer_req(timer::TimerMsg::Dhcp6ReplyWaitTimeout, rt);
                                self.dhcp6c_last_rt = rt;
                            }
                            IpoedMode::Pd => {
                                if self.dhcp6c_req_sent_count == dhcp6::REQ_MAX_RC {
                                    if let Err(e) = self.reset() {
                                        println!("Reset error: {e}");
                                    }
                                    if let Err(e) = self.commit() {
                                        println!("Commit error: {e}");
                                    }
                                    return;
                                }
                                self.send_req(true);
                                let rt = self.dhcp6c_rt(dhcp6::REQ_MAX_RT);
                                self.timer_req(timer::TimerMsg::Dhcp6ReplyWaitTimeout, rt);
                                self.dhcp6c_last_rt = rt;
                            }
                            IpoedMode::Init => {
                                println!("XXX: BUG? IpoedMode is still Init");
                                return;
                            }
                        }
                    }
                }
                _ => {
                    if self.debug {
                        println!("recv_timer_msg: msg={:?} state={:?}", msg, self.state);
                    }
                }
            },
            timer::TimerMsg::Dhcp6RenewingTimeout => match self.state {
                IpoedState::Dhcp6Renewing => {
                    self.send_ren(true);
                    let rt = self.dhcp6c_rt(dhcp6::REN_MAX_RT);
                    self.timer_req(timer::TimerMsg::Dhcp6RenewingTimeout, rt);
                    self.dhcp6c_last_rt = rt;
                }
                _ => {
                    if self.debug {
                        println!("recv_timer_msg: msg={:?} state={:?}", msg, self.state);
                    }
                }
            },
            timer::TimerMsg::PeriodicFire => {
                self.periodic_check();
                self.periodic_send_ra();
                self.periodic_gc_na();
                if !self.disable_hb46pp {
                    self.periodic_hb46pp();
                }
                self.timer_req(timer::TimerMsg::PeriodicFire, PERIODIC_INTERVAL);
            }
        }
    }

    pub fn recv_rtnl_msg(&mut self, msg: rtnl::RtnlMsg) {
        match msg {
            rtnl::RtnlMsg::WanLinkDown => {
                println!("WAN interface link down");
                // TODO:
            }
            rtnl::RtnlMsg::WanLinkUp => {
                println!("WAN interface link up");
                // TODO:
            }
            rtnl::RtnlMsg::LanLinkDown => {
                println!("LAN interface link down");
            }
            rtnl::RtnlMsg::LanLinkUp => {
                println!("LAN interface link up");
            }
        }
    }

    pub fn recv_icmp6_msg(&mut self, pkt: icmp6::Icmp6Pkt) {
        if self.debug {
            println!("Received ICMPv6 message: msg={:?}", pkt);
        }
        let src = if let Some(src) = pkt.src {
            src
        } else {
            println!(
                "XXX: BUG? ICMPv6 message has no source address: msg={:?}",
                pkt
            );
            return;
        };
        match pkt.msg {
            icmp6::Icmp6Msg::RtSolicit(_msg) => {
                if !self.is_lan_if(&pkt.iif) {
                    return;
                }
                self.send_ra(Some(&src), false);
            }
            icmp6::Icmp6Msg::RtAdvert(msg) => {
                if !self.is_wan_if(&pkt.iif) {
                    return;
                }
                'out: {
                    match self.state {
                        IpoedState::Icmp6RaWaiting => {
                            // Router Lifetime の RA は無視。
                            if msg.router_lifetime == 0 {
                                println!("Ignoring ICMPv6 RA with router_lifetime=0 from {src}");
                                break 'out;
                            }
                            if msg.prefix_infos.len() > 0 && msg.flags.has_other_config() {
                                // RA
                                println!("Entering ICMPv6 RA mode");
                                if let Err(e) = rtnl::set_promisc(self.wan_if_index, true) {
                                    println!("Set WAN interface promisc on failed: {e}");
                                }
                                self.prefix_can = Some(msg.prefix_infos[0].prefix.clone());
                                self.mode = IpoedMode::Ra;
                                self.send_inf(false);
                                let rt = self.dhcp6c_rt_init(dhcp6::INF_TIMEOUT);
                                self.timer_req(timer::TimerMsg::Dhcp6ReplyWaitTimeout, rt);
                                self.dhcp6c_last_rt = rt;
                                self.state = IpoedState::Dhcp6ReplyWaiting;
                            } else if msg.flags.has_managed_addr_config() {
                                // DHCPv6-PD
                                println!("Entering DHCPv6 PD mode");
                                self.mode = IpoedMode::Pd;
                                self.send_sol(true, false);
                                let rt = self.dhcp6c_rt_init(dhcp6::SOL_TIMEOUT);
                                self.timer_req(timer::TimerMsg::Dhcp6AdvertWaitTimeout, rt);
                                self.dhcp6c_last_rt = rt;
                                self.state = IpoedState::Dhcp6AdvertWaiting;
                            } else {
                                println!("ICMPv6 RA without M or O flags");
                                break 'out;
                            }
                            self.gateway_can = Some(src.clone());
                        }
                        _ => {
                            if self.debug {
                                println!("recv_icmp6_msg: msg={:?} state={:?}", msg, self.state);
                            }
                        }
                    }
                }
                self.icmp6c_ras.insert(src, (msg, Instant::now()));
            }
            icmp6::Icmp6Msg::NeighSolicit(msg) => {
                if !self.is_wan_if(&pkt.iif) {
                    return;
                }
                if msg.tgt_addr.is_unicast_link_local() {
                    return;
                }
                if self.mode != IpoedMode::Ra {
                    return;
                }
                let dst_addr = if src.is_unspecified() {
                    None
                } else {
                    Some(&src)
                };
                if let Some(hb46pp) = &self.hb46pp_run {
                    if let Some(ipv6_local) = &hb46pp.ipv6_local {
                        // HB46PP のトンネル終端アドレスの場合
                        if &msg.tgt_addr == ipv6_local {
                            self.send_na(dst_addr, self.wan_if_hw_addr, &msg.tgt_addr);
                            return;
                        }
                    }
                }
                if let Some(prefix) = &self.prefix_run {
                    let lan_addr = utils::ipv6_address(prefix, &self.lan_iid);
                    if &msg.tgt_addr == &lan_addr {
                        // 自身の LAN 側 IPv6 アドレスの場合
                        self.send_na(dst_addr, self.wan_if_hw_addr, &msg.tgt_addr);
                        return;
                    }
                }
                if let Some((na, _)) = self.icmp6s_nas.get(&msg.tgt_addr) {
                    let tgt_addr = na.tgt_addr.clone();
                    self.send_na(dst_addr, self.wan_if_hw_addr, &tgt_addr);
                } else {
                    self.send_ns(&msg.tgt_addr);
                }
            }
            icmp6::Icmp6Msg::NeighAdvert(msg) => {
                if !self.is_lan_if(&pkt.iif) {
                    return;
                }
                if msg.tgt_addr.is_unicast_link_local() {
                    return;
                }
                if self.debug {
                    println!("Insert ICMPv6 NA cache: {} {:?}", msg.tgt_addr, msg);
                }
                self.icmp6s_nas
                    .insert(msg.tgt_addr.clone(), (msg, Instant::now()));
            }
            icmp6::Icmp6Msg::Redirect(_msg) => {}
        }
    }

    pub fn recv_dhcp6_msg(&mut self, pkt: dhcp6::Dhcp6Pkt) {
        if self.debug {
            println!("Received DHCPv6 message: msg={:?}", pkt);
        }
        let src = if let Some(src) = pkt.src {
            src
        } else {
            println!(
                "XXX: BUG? DHCPv6 message has no source address: msg={:?}",
                pkt
            );
            return;
        };
        match pkt.msg {
            dhcp6::Dhcp6Msg::Solicit(_msg) => {}
            dhcp6::Dhcp6Msg::Advertise(msg) => {
                if !self.is_wan_if(&pkt.iif) {
                    return;
                }
                if msg.transaction_id != self.dhcp6c_last_tid {
                    println!(
                        "Transaction ID mismatch: expected={}, got={}, src={}",
                        self.dhcp6c_last_tid, msg.transaction_id, src
                    );
                    return;
                }
                match self.state {
                    IpoedState::Dhcp6AdvertWaiting => {
                        // タイムアウト時に処理をするのでこの時点では何もしない。
                        println!("Received DHCPv6 Advertise for Solicit from {}", src);
                    }
                    _ => {
                        if self.debug {
                            println!("recv_dhcp6_msg: msg={:?} state={:?}", msg, self.state);
                        }
                    }
                }
                self.dhcp6c_advs.insert(src, (msg, Instant::now()));
            }
            dhcp6::Dhcp6Msg::Request(_msg) => {}
            dhcp6::Dhcp6Msg::Confirm(_msg) => {}
            dhcp6::Dhcp6Msg::Renew(_msg) => {}
            dhcp6::Dhcp6Msg::Rebind(_msg) => {}
            dhcp6::Dhcp6Msg::Decline(_msg) => {}
            dhcp6::Dhcp6Msg::Release(_msg) => {}
            dhcp6::Dhcp6Msg::Reply(msg) => {
                if !self.is_wan_if(&pkt.iif) {
                    return;
                }
                if msg.transaction_id != self.dhcp6c_last_tid {
                    println!(
                        "Transaction ID mismatch: expected={}, got={}, src={}",
                        self.dhcp6c_last_tid, msg.transaction_id, src
                    );
                    return;
                }
                match self.state {
                    IpoedState::Dhcp6ReplyWaiting => {
                        // タイムアウト時に処理をするのでこの時点では何もしない。
                        println!("Received DHCPv6 Reply for Request/I-R from {}", src);
                    }
                    IpoedState::Dhcp6Renewing => {
                        println!("Received DHCPv6 Reply for Renew from {}", src);
                        self.state = IpoedState::Ready;
                    }
                    _ => {
                        if self.debug {
                            println!("recv_dhcp6_msg: msg={:?} state={:?}", msg, self.state);
                        }
                    }
                }
                self.dhcp6c_reps.insert(src, (msg, Instant::now()));
            }
            dhcp6::Dhcp6Msg::Reconf(_msg) => {}
            dhcp6::Dhcp6Msg::InfoReq(msg) => {
                if !self.is_lan_if(&pkt.iif) {
                    return;
                }
                self.send_rep(msg.transaction_id, &src, &msg.client_id);
            }
            dhcp6::Dhcp6Msg::RelayForward(_msg) => {}
            dhcp6::Dhcp6Msg::RelayReply(_msg) => {}
        }
    }

    pub fn recv_hb46pp_msg(&mut self, msg: hb46pp::Hb46ppRep) {
        println!("Received HB46PP reply: {:?}", msg);
        if !self.ipv6_ready() {
            println!("but IPv6 is not ready");
            return;
        }
        let changed = if let Ok(config) = msg.config {
            self.hb46pp_can = Some(config);
            true
        } else if msg.reset {
            self.hb46pp_can = None;
            true
        } else {
            false
        };
        if changed {
            if let Err(e) = self.commit() {
                println!("Commit failed: {e}");
                return;
            }
        }
        self.hb46pp_next = Instant::now() + msg.wait;
    }

    fn periodic_check(&mut self) {
        if !self.ipv6_ready() {
            return;
        }
        let now = Instant::now();
        let gateway = if let Some(gateway) = &self.gateway_run {
            gateway
        } else {
            println!("Ready state but gateway is missing");
            return;
        };
        let prefix = if let Some(prefix) = &self.prefix_run {
            prefix
        } else {
            println!("Ready state but prefix is missing");
            return;
        };
        let (ra, received) = if let Some((ra, received)) = self.icmp6c_ras.get(gateway) {
            (ra, *received)
        } else {
            println!("Ready state but no ICMPv6 RA is cached");
            return;
        };
        // RA の有効期限が失効していた時は初期状態にリセットする。
        let duration = Duration::from_secs(ra.router_lifetime.into());
        if ra.router_lifetime == 0 || received + duration < now {
            println!("ICMPv6 RA router lifetime expired");
            self.send_ra(None, true);
            if let Err(e) = self.reset() {
                println!("Reset error: {e}");
            }
            if let Err(e) = self.commit() {
                println!("Commit error: {e}");
            }
            return;
        }
        // IPv6 プレフィックスの有効期限を収集する。
        let (last_received, valid_lifetime) = match self.mode {
            IpoedMode::Ra => {
                let mut valid_lifetime: Option<u32> = None;
                for prefix_info in &ra.prefix_infos {
                    if prefix_info.prefix == *prefix {
                        valid_lifetime = Some(prefix_info.valid_lifetime);
                    }
                }
                if valid_lifetime.is_none() {
                    println!("Matching prefix not found in cached ICMPv6 RA");
                    return;
                }
                (received, valid_lifetime.unwrap())
            }
            IpoedMode::Pd => {
                let rep = if let Some((rep, _)) = self.dhcp6c_reps.get(gateway) {
                    rep
                } else {
                    println!("Ready state but no DHCPv6 Reply is cached");
                    return;
                };
                let mut valid_lifetime: Option<u32> = None;
                for ia_pd in &rep.ia_pds {
                    for ia_prefix in &ia_pd.ia_prefixes {
                        if ia_prefix.ipv6_prefix == *prefix {
                            valid_lifetime = Some(ia_prefix.valid_lifetime);
                        }
                    }
                }
                if valid_lifetime.is_none() {
                    println!("DHCPv6 Reply does not contain a matching IA_PD prefix");
                    return;
                }
                (received, valid_lifetime.unwrap())
            }
            IpoedMode::Init => {
                println!("XXX: BUG? IpoedMode is still Init");
                return;
            }
        };
        // もし IPv6 プレフィクスの有効期限が失効していた時も初期状態にリセットする。
        let duration = Duration::from_secs(valid_lifetime.into());
        if last_received + duration < now {
            println!("Prefix valid lifetime expired");
            self.send_ra(None, true);
            if let Err(e) = self.reset() {
                println!("Reset error: {e}");
            }
            if let Err(e) = self.commit() {
                println!("Commit error: {e}");
            }
            return;
        }
        // DHCPv6-PD の時は T1 時間以上経過していたら Renew する。
        if self.mode == IpoedMode::Pd && self.state == IpoedState::Ready {
            let (rep, received) = if let Some((rep, received)) = self.dhcp6c_reps.get(gateway) {
                (rep, received)
            } else {
                println!("Ready state but no DHCPv6 Reply is cached");
                return;
            };
            let mut t1: Option<u32> = None;
            for ia_pd in &rep.ia_pds {
                for ia_prefix in &ia_pd.ia_prefixes {
                    if ia_prefix.ipv6_prefix == *prefix {
                        t1 = Some(ia_pd.t1);
                    }
                }
            }
            let t1 = if let Some(t1) = t1 {
                t1
            } else {
                println!("DHCPv6 Reply does not contain a matching IA_PD prefix");
                return;
            };
            let duration = Duration::from_secs(t1.into());
            if *received + duration < now {
                println!(
                    "DHCPv6 T1 expired: t1={}, received_at={:?}, now={:?}",
                    t1, *received, now
                );
                self.send_ren(false);
                let rt = self.dhcp6c_rt_init(dhcp6::REN_TIMEOUT);
                self.timer_req(timer::TimerMsg::Dhcp6RenewingTimeout, rt);
                self.dhcp6c_last_rt = rt;
                self.state = IpoedState::Dhcp6Renewing;
            }
        }
    }

    fn periodic_send_ra(&mut self) {
        if !self.ipv6_ready() {
            return;
        }
        let now = Instant::now();
        if now > self.icmp6s_next_ts {
            let router_lifetime = self.send_ra(None, false);
            let (mut min, mut max) = if router_lifetime > 0 {
                (
                    router_lifetime as u64 * 1000 / 3,
                    router_lifetime as u64 * 1000,
                )
            } else {
                (
                    icmp6::IPOED_MIN_RTR_ADV_INTERVAL,
                    icmp6::IPOED_MAX_RTR_ADV_INTERVAL,
                )
            };
            if min > icmp6::IPOED_MIN_RTR_ADV_INTERVAL {
                min = icmp6::IPOED_MIN_RTR_ADV_INTERVAL;
            }
            if max > icmp6::IPOED_MAX_RTR_ADV_INTERVAL {
                max = icmp6::IPOED_MAX_RTR_ADV_INTERVAL;
            }
            self.icmp6s_next_ts = now + Duration::from_millis(rand::random_range(min..max));
        }
    }

    fn periodic_gc_na(&mut self) {
        let mut dels = Vec::<(Ipv6Addr, icmp6::NeighAdvertMsg)>::new();
        let now = Instant::now();
        let duration = Duration::from_secs(60); // XXX: REACHABLE_TIME * 2
        for (tgt, (na, received)) in &self.icmp6s_nas {
            if now > *received + duration {
                dels.push((tgt.clone(), na.clone()));
            }
        }
        for del in &dels {
            if self.debug {
                println!("Remove ICMPv6 NA cache: {} {:?}", del.0, del.1);
            }
            self.icmp6s_nas.remove(&del.0);
        }
    }

    fn periodic_hb46pp(&mut self) {
        if !self.ipv6_ready() {
            return;
        }
        let now = Instant::now();
        if now < self.hb46pp_next {
            return;
        }
        println!("Sending HB46PP request");
        if let Err(e) = self.hb46pp_tx.send(hb46pp::Hb46ppReq {
            user: self.hb46pp_user.clone(),
            pass: self.hb46pp_pass.clone(),
        }) {
            println!("Failed to send HB46PP request: {e}");
        }
        // リプライで次の起動時刻が更新されるがそれまでの仮で一時間後に設定。
        self.hb46pp_next = now + Duration::from_secs(3600);
    }
}
