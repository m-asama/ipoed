// SPDX-License-Identifier: MIT
// Copyright(c) 2026 Masakazu Asama

use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use resolv::record::AAAA;
use resolv::{Class, RecordType, Resolver};

use crate::hb46pp::Hb46ppMsg;

#[derive(Clone, Debug, PartialEq)]
pub enum Hb46ppProto {
    DsLite,
    Ipip,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Hb46ppConfig {
    pub proto: Hb46ppProto,
    pub ipv6_remote: Ipv6Addr,
    pub ipv6_local: Option<Ipv6Addr>,
    pub ipv4: Option<(Ipv4Addr, u8)>,
}

impl TryFrom<Hb46ppMsg> for Hb46ppConfig {
    type Error = String;
    fn try_from(msg: Hb46ppMsg) -> Result<Self, Self::Error> {
        for proto in &msg.order {
            if let Some(dslite) = &msg.dslite
                && proto == "dslite"
            {
                if let Ok(ipv6_remote) = Ipv6Addr::from_str(&dslite.aftr) {
                    return Ok(Hb46ppConfig {
                        proto: Hb46ppProto::DsLite,
                        ipv6_remote: ipv6_remote.clone(),
                        ipv6_local: None,
                        ipv4: None,
                    });
                }
                let mut resolver = match Resolver::new() {
                    Some(resolver) => resolver,
                    None => {
                        println!("Resolver error:");
                        continue;
                    }
                };
                let mut response =
                    match resolver.query(dslite.aftr.as_bytes(), Class::IN, RecordType::ANY) {
                        Ok(response) => response,
                        Err(e) => {
                            println!("Query error: {e}");
                            continue;
                        }
                    };
                for answer in response.answers::<AAAA>() {
                    return Ok(Hb46ppConfig {
                        proto: Hb46ppProto::DsLite,
                        ipv6_remote: answer.data.address,
                        ipv6_local: None,
                        ipv4: None,
                    });
                }
                for answer in response.additional_records::<AAAA>() {
                    return Ok(Hb46ppConfig {
                        proto: Hb46ppProto::DsLite,
                        ipv6_remote: answer.data.address,
                        ipv6_local: None,
                        ipv4: None,
                    });
                }
                println!("dslite parse failed");
            }
            if msg.ipip.len() > 0 && proto == "ipip" {
                let ipip = &msg.ipip[0];
                let ipv6_remote = match Ipv6Addr::from_str(&ipip.ipv6_remote) {
                    Ok(ipv6_remote) => ipv6_remote,
                    Err(e) => {
                        println!("ipv6_remote parse error: {e}");
                        continue;
                    }
                };
                let ipv6_local = match Ipv6Addr::from_str(&ipip.ipv6_local) {
                    Ok(ipv6_local) => ipv6_local,
                    Err(e) => {
                        println!("ipv6_local parse error: {e}");
                        continue;
                    }
                };
                let ipv4pl: Vec<&str> = ipip.ipv4.splitn(2, '/').collect::<Vec<&str>>();
                if ipv4pl.len() != 2 {
                    println!("ipv4 parse error");
                    continue;
                }
                let ipv4p = match Ipv4Addr::from_str(&ipv4pl[0]) {
                    Ok(ipv4p) => ipv4p,
                    Err(e) => {
                        println!("ipv4 parse error: {e}");
                        continue;
                    }
                };
                let ipv4l = match u8::from_str(&ipv4pl[1]) {
                    Ok(ipv4l) => ipv4l,
                    Err(e) => {
                        println!("ipv4 parse error: {e}");
                        continue;
                    }
                };
                return Ok(Hb46ppConfig {
                    proto: Hb46ppProto::Ipip,
                    ipv6_remote: ipv6_remote,
                    ipv6_local: Some(ipv6_local),
                    ipv4: Some((ipv4p, ipv4l)),
                });
            }
        }
        Err(format!("Not supported"))
    }
}
