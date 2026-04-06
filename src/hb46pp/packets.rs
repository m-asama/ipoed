// SPDX-License-Identifier: MIT
// Copyright(c) 2026 Masakazu Asama

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct MapRule {
    pub ipv6: String,
    pub ipv4: String,
    pub ea_length: u8,
    pub psid_offset: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MapEOpt {
    pub version: Option<u8>,
    pub mesh: Option<u8>,
    pub br: String,
    pub rules: Vec<MapRule>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DsLiteOpt {
    pub aftr: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Lw4o6Opt {
    pub lwaftr: String,
    pub ipv6: String,
    pub ipv4: String,
    pub psid: u16,
    pub psid_length: u8,
    pub psid_offset: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MapTOpt {
    pub version: Option<u8>,
    pub mesh: Option<u8>,
    pub br: String,
    pub rules: Vec<MapRule>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsfXlatOpt {
    pub nat64prefix: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IpipOpt {
    pub ipv6_local: String,
    pub ipv6_remote: String,
    pub ipv4: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Hb46ppMsg {
    pub enabler_name: String,
    pub service_name: String,
    pub isp_name: Option<String>,
    pub ttl: Option<u64>,
    pub token: Option<String>,
    pub auth: Option<String>,
    pub order: Vec<String>,
    pub ipv6_mostly: Option<bool>,
    pub map_e: Option<MapEOpt>,
    pub dslite: Option<DsLiteOpt>,
    pub lw4o6: Option<Lw4o6Opt>,
    pub map_t: Option<MapTOpt>,
    #[serde(rename = "464xlat")]
    pub fsfxlat: Option<FsfXlatOpt>,
    pub ipip: Vec<IpipOpt>,
}
