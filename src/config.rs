// SPDX-License-Identifier: MIT
// Copyright(c) 2026 Masakazu Asama

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;

pub const DEFAULT_HOOK_PATH: &str = "/usr/libexec/ipoed/hook";

pub fn usage() {
    println!("Usage: ipoed --wan-if <WAN_IF> --lan-if <LAN_IF> --lan-iid <LAN_IID>...");
    println!("");
    println!("Options:");
    println!("    -w, --wan-if <WAN_IF>          WAN interface (Required)");
    println!("    -l, --lan-if <LAN_IF>          LAN interface (Required)");
    println!("    -i, --lan-iid <LAN_IID>        LAN IID (Default: SLAAC)");
    println!("    -s, --dns-server-self          Set DHCPv6 DNS server self");
    println!("    -4, --lan-addr4 <LAN_ADDR4>    LAN IPv4 address (Default none)");
    println!("    -H, --disable-hb46pp           Disable HB46PP");
    println!("    -u, --hb46pp-user <USER>       HB46PP user");
    println!("    -p, --hb46pp-pass <PASS>       HB46PP pass");
    println!("    -e, --hook-path <HOOK_PATH>    Hook path");
    println!("    -d, --debug                    Enable debug");
    println!("    -h, --help                     Print help");
    println!("");
}

pub struct Config {
    pub wan_if: Option<String>,
    pub lan_if: Option<String>,
    pub lan_iid: Option<Ipv6Addr>,
    pub dns_server_self: bool,
    pub lan_addr4: Option<(Ipv4Addr, u8)>,
    pub disable_hb46pp: bool,
    pub hb46pp_user: Option<String>,
    pub hb46pp_pass: Option<String>,
    pub hook_path: String,
    pub debug: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            wan_if: None,
            lan_if: None,
            lan_iid: None,
            dns_server_self: false,
            lan_addr4: None,
            disable_hb46pp: false,
            hb46pp_user: None,
            hb46pp_pass: None,
            hook_path: DEFAULT_HOOK_PATH.to_string(),
            debug: false,
        }
    }
}

impl Config {
    pub fn from_args() -> Result<Self, String> {
        let mut conf = Self::default();
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_ref() {
                "-w" | "--wan-if" => {
                    conf.wan_if = args.next();
                }
                "-l" | "--lan-if" => {
                    conf.lan_if = args.next();
                }
                "-i" | "--lan-iid" => {
                    let lan_iid_str = match args.next() {
                        Some(lan_iid_str) => lan_iid_str,
                        None => return Err(format!("IID required")),
                    };
                    conf.lan_iid = match Ipv6Addr::from_str(&lan_iid_str) {
                        Ok(lan_iid) => Some(lan_iid),
                        Err(e) => return Err(format!("IID format error: {e}")),
                    };
                }
                "-s" | "--dns-server-self" => {
                    conf.dns_server_self = true;
                }
                "-4" | "--lan-addr4" => {
                    let addr4_plen_str = match args.next() {
                        Some(addr4_plen_str) => addr4_plen_str,
                        None => return Err(format!("IPv4 address required")),
                    };
                    let addr4_plen: Vec<&str> =
                        addr4_plen_str.splitn(2, '/').collect::<Vec<&str>>();
                    if addr4_plen.len() != 2 {
                        return Err(format!("IPv4 address format error"));
                    }
                    let addr4 = match Ipv4Addr::from_str(&addr4_plen[0]) {
                        Ok(addr4) => addr4,
                        Err(e) => return Err(format!("IPv4 address format error: {e}")),
                    };
                    let plen = match u8::from_str(&addr4_plen[1]) {
                        Ok(plen) => plen,
                        Err(e) => return Err(format!("IPv4 address format error: {e}")),
                    };
                    conf.lan_addr4 = Some((addr4, plen));
                }
                "-H" | "--disable-hb46pp" => {
                    conf.disable_hb46pp = true;
                }
                "-u" | "--hb46pp-user" => {
                    conf.hb46pp_user = match args.next() {
                        Some(hb46pp_user) => Some(hb46pp_user),
                        None => return Err(format!("HB46PP user required")),
                    };
                }
                "-p" | "--hb46pp-pass" => {
                    conf.hb46pp_pass = match args.next() {
                        Some(hb46pp_pass) => Some(hb46pp_pass),
                        None => return Err(format!("HB46PP pass required")),
                    };
                }
                "-e" | "--hook-path" => {
                    conf.hook_path = match args.next() {
                        Some(hook_path) => hook_path,
                        None => return Err(format!("Hook path required")),
                    };
                }
                "-d" | "--debug" => {
                    conf.debug = true;
                }
                "-h" | "--help" => {
                    return Err(String::new());
                }
                _ => {
                    return Err(format!("Unknown argument"));
                }
            }
        }
        Ok(conf)
    }
}
