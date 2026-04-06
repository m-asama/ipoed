// SPDX-License-Identifier: MIT
// Copyright(c) 2026 Masakazu Asama

mod dhcp6;
mod hb46pp;
mod hook;
mod icmp6;
mod rtnl;
mod timer;
mod utils;

mod config;
use config::*;

mod context;
use context::*;

#[derive(Debug)]
enum IpoedMsg {
    Timer(timer::TimerMsg),
    Rtnl(rtnl::RtnlMsg),
    Icmp6(icmp6::Icmp6Pkt),
    Dhcp6(dhcp6::Dhcp6Pkt),
    Hb46pp(hb46pp::Hb46ppRep),
}

fn main() {
    let conf = match Config::from_args() {
        Ok(conf) => conf,
        Err(e) => {
            if e.len() > 0 {
                println!("Config parse error: {e}");
            }
            usage();
            return;
        }
    };
    let mut ctx = match Context::from_conf(conf) {
        Ok(ctx) => ctx,
        Err(e) => {
            println!("Context init error: {e}");
            return;
        }
    };
    if let Err(e) = ctx.setup() {
        println!("Setup error: {e}");
        return;
    }
    if let Err(e) = rtnl::init(ctx.ch_tx.clone(), ctx.wan_if_index, ctx.lan_if_index) {
        println!("Rtnl init error: {e}");
        return;
    }
    ctx.sk_icmp6 = match icmp6::init(ctx.ch_tx.clone(), ctx.wan_if_index, ctx.lan_if_index) {
        Ok(sk_icmp6) => sk_icmp6,
        Err(e) => {
            println!("ICMPv6 init error: {e}");
            return;
        }
    };
    (ctx.sk_dhcp6s, ctx.sk_dhcp6c) = match dhcp6::init(ctx.ch_tx.clone(), ctx.lan_if_index) {
        Ok((sk_dhcp6s, sk_dhcp6c)) => (sk_dhcp6s, sk_dhcp6c),
        Err(e) => {
            println!("DHCPv6 init error: {e}");
            return;
        }
    };
    ctx.timer_req(
        timer::TimerMsg::RsSolicitSendDelayTimeout,
        rand::random_range(0..icmp6::MAX_RTR_SOLICITATION_DELAY),
    );
    ctx.timer_req(timer::TimerMsg::PeriodicFire, PERIODIC_INTERVAL);
    loop {
        match ctx.ch_rx.recv() {
            Ok(msg) => match msg {
                IpoedMsg::Timer(msg) => ctx.recv_timer_msg(msg),
                IpoedMsg::Rtnl(msg) => ctx.recv_rtnl_msg(msg),
                IpoedMsg::Icmp6(msg) => ctx.recv_icmp6_msg(msg),
                IpoedMsg::Dhcp6(msg) => ctx.recv_dhcp6_msg(msg),
                IpoedMsg::Hb46pp(msg) => ctx.recv_hb46pp_msg(msg),
            },
            Err(e) => {
                println!("Channel receive error: {e}");
                return;
            }
        }
    }
}
